// Vercel Serverless Function: /api/device/register
// ログイン成功後（セッションCookieがある状態）に呼ぶ想定のAPI。
// devicesテーブルに status=pending で新規UUIDを発行し、
// 確認画面（スクショしてDiscordで送る用）に表示するための
// UUID・member_id・発行時刻などを返す。
//
// [前提]
// ・requireAuth（./_lib/auth.js）でセッションCookieを検証する。
//   ここでは role は問わない（ログイン済みであれば誰でも自分の端末を登録できる）。
// ・devices.id / status / issued_at / expires_at はテーブル側の DEFAULT に任せる
//   （id: gen_random_uuid(), status: 'pending', issued_at: now(),
//    expires_at: now() + 30日）。expires_at は承認前は意味を持たないが、
//    スキーマ上 NOT NULL のため DEFAULT 値がそのまま入る。
//    承認後の実際の有効期限管理・sliding window延長は④(/api/device/verify)で行う。
//
// [モジュール形式]
// このアプリの /api 配下は chars.js / login.js と同じ CommonJS で統一。
//
// [DB往復回数について（軽量化）]
// 旧実装は「同一端末(UA一致)の重複チェック用select」と「登録数カウント用のcount
// select」を別々に投げていたが、同じ member_id の devices を1回のselectで
// まとめて取得し、重複判定（UA一致するものがあるか）と件数チェック（配列の
// length）の両方をJS側で行うことで、往復を1回減らしている。

const { createClient } = require('@supabase/supabase-js')
const { requireAuth } = require('../_lib/auth')

// 1メンバーが同時に持てる端末登録数の上限（pending/approved問わずカウント）。
// これを超える場合は新規登録を拒否し、管理者に不要な端末のrevokeを依頼させる。
// セッション乗っ取り等でregisterが連打され、無制限にdeviceId（＝実質の永続認証情報）
// が量産されるのを防ぐための歯止め。
const MAX_DEVICES_PER_MEMBER = 3

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    res.status(405).json({ error: 'Method Not Allowed' })
    return
  }

  // 認証チェック（ログイン済みであることのみ確認。role指定なし）
  const auth = await requireAuth(req, res, null)
  if (!auth) return // requireAuth内で401/403レスポンス済み

  const { memberId } = auth

  const SUPABASE_URL = process.env.SUPABASE_URL
  const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY

  if (!SUPABASE_URL || !SERVICE_KEY) {
    console.error('SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY が未設定です')
    res.status(500).json({ error: 'サーバー設定エラーが発生しました' })
    return
  }

  const supabase = createClient(SUPABASE_URL, SERVICE_KEY)

  try {
    // 確認画面にメンバー名も出せるよう、name も一緒に引いておく
    // （存在しない/無効化されている場合はここで弾く。通常はrequireAuthの
    //   invalidate_beforeチェックを通過している時点でauth_roleは生きているが、
    //   members.status の無効化はJWT検証だけでは分からないため、ここで確認する）
    const { data: member, error: memberErr } = await supabase
      .from('members')
      .select('id, name, status')
      .eq('id', memberId)
      .maybeSingle()

    if (memberErr) {
      console.error('members取得エラー:', memberErr)
      res.status(500).json({ error: 'サーバーエラーが発生しました' })
      return
    }

    if (!member || member.status === '無効') {
      res.status(403).json({ error: 'アカウントが無効化されています' })
      return
    }

    const userAgent = req.headers['user-agent'] || null

    // 同一メンバーのdevicesを1回でまとめて取得し、
    //   1) 同一端末（UA完全一致）の重複チェック
    //   2) 登録済み端末数の上限チェック（count用の別クエリを廃止し、この配列のlengthを使う）
    // の両方をJS側で行う。
    //
    // 同一端末判定の考え方（元コメントのまま）：
    // 例：iPhoneのSafariでログイン→ホーム画面に追加→そこから開くと、
    // localStorageがSafariとホーム画面アプリ(スタンドアロン表示)で別々になるため、
    // クライアント側だけでは「同じ端末だ」と判定できず、registerが2回呼ばれてしまう。
    // ただしiOSではSafariとホーム画面追加後のUser-Agentはほぼ同一文字列になるため、
    // ここでは member_id + User-Agent の完全一致を「同一端末」とみなし、
    // 既存行があれば新規発行せずそれを使い回す（＝上書き）。
    // 一方、同じIDでもスマホとPCはUser-Agentが明確に異なるため別端末として扱われる。
    //
    // 注意（既知の限界）：全く同じ機種・同じOS/ブラウザのバージョンを使う
    // 2台の異なる端末は、User-Agentだけでは区別できず誤って同一端末とみなされる
    // 可能性がある。より厳密にやるならクライアント側で生成した永続フィンガープリント等
    // 追加の識別子が必要だが、今回の要件（同一端末からの二重登録防止）には
    // このUser-Agent一致判定で十分と判断した。
    const { data: memberDevices, error: devicesErr } = await supabase
      .from('devices')
      .select('id, member_id, status, issued_at, expires_at, user_agent')
      .eq('member_id', memberId)

    if (devicesErr) {
      console.error('devices取得エラー:', devicesErr)
      res.status(500).json({ error: 'サーバーエラーが発生しました' })
      return
    }

    const devices = memberDevices || []

    const existing = userAgent
      ? devices.find(d => d.user_agent === userAgent)
      : devices.find(d => d.user_agent == null)

    if (existing) {
      // 同一端末（同一UA）の登録が既にある場合は新規発行せず、
      // その端末情報をそのまま返す（ステータス・発行時刻は変更しない）。
      res.status(200).json({
        ok: true,
        deviceId: existing.id,
        memberId: existing.member_id,
        memberName: member.name,
        status: existing.status,
        issuedAt: existing.issued_at,
        reused: true, // 新規申請ではなく既存端末を再利用したことをフロントで判別可能にする
      })
      return
    }

    // 登録済み端末数の上限チェック（revoke済みは行自体が削除される運用のため、
    // 現存する行数 = pending + approved の合計をそのまま数えればよい）
    if (devices.length >= MAX_DEVICES_PER_MEMBER) {
      res.status(429).json({
        error: `登録できる端末数の上限（${MAX_DEVICES_PER_MEMBER}台）に達しています。使わなくなった端末を管理者に無効化してもらってください。`,
      })
      return
    }

    const { data: device, error: insertErr } = await supabase
      .from('devices')
      .insert({
        member_id: memberId,
        user_agent: userAgent,
        // status / issued_at / expires_at はテーブルのDEFAULTに任せる
      })
      .select('id, member_id, status, issued_at, expires_at')
      .single()

    if (insertErr) {
      console.error('devices登録エラー:', insertErr)
      res.status(500).json({ error: '端末情報の登録に失敗しました' })
      return
    }

    // フロントの確認画面（スクショ→Discord手動送付）用データ
    res.status(200).json({
      ok: true,
      deviceId: device.id,
      memberId: device.member_id,
      memberName: member.name,
      status: device.status,
      issuedAt: device.issued_at,
    })
  } catch (e) {
    console.error(e)
    res.status(500).json({ error: 'サーバーエラーが発生しました' })
  }
}