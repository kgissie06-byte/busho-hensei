// Vercel Serverless Function: /api/device/verify
// クライアント側(localStorage等)に保存されたdeviceId(UUID)を検証するAPI。
// ログイン画面を経由せず、このAPIだけで「実質のログイン」を完結させる想定。
//
// [フロー]
// 1. devices テーブルを deviceId で検索（members・auth_roleもネストselectで同時取得）
// 2. status / expires_at / members.status / auth_role の有無を順番にチェック
// 3. 全て問題なければ、
//    - expires_at を now()+30日に更新（sliding window）
//      ※直近 SLIDING_WINDOW_THROTTLE_MS 以内に更新済みならUPDATEをスキップし、
//        毎回のアプリ起動でDB書き込みが発生しないようにする（無駄な通信/書き込みの削減）
//    - last_seen_at・user_agent を更新（同様に間引き対象）
//    - ./_lib/auth.js の issueSession でJWTセッションCookieを発行
//      （以降は他のAPIで requireAuth によるCookie認証がそのまま使える）
// 4. どこかの段階で拒否する場合は、理由(reason)付きで401/403を返す
//    ※ login.jsとは違い、こちらは「IDの存在を隠す」必要がないので
//      reasonを具体的に返してフロント側で適切な画面分岐をできるようにする
//      （例: pending→承認待ち画面、revoked/expired→ログイン画面に戻す 等）
//
// [DB往復回数について（軽量化）]
// 旧実装は devices取得 → members取得 → auth_role取得 → devices更新 の最大4往復。
// PostgRESTのネストselect（admin.jsの devices→members と同じ書き方）で
// devices→members→auth_role を1クエリにまとめ、往復を大幅に削減している。
// ※ 前提：以下のFK制約名が実際のDBと一致していること（無ければPostgRESTが
//   エラーを返すので、その場合は実際の制約名に置き換えてください）
//   - devices.member_id  -> members.id   （制約名: devices_member_id_fkey）
//   - auth_role.member_id -> members.id  （制約名: auth_role_member_id_fkey）
//
// [モジュール形式] chars.js / login.js と同じ CommonJS

const { createClient } = require('@supabase/supabase-js')
const { issueSession } = require('../_lib/auth')

// UUID形式の簡易バリデーション（v4に限定せず、ハイフン区切りの16進形式であれば許容）
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

// sliding window更新（UPDATE）の間引き間隔。
// この時間内に last_seen_at が更新済みなら、今回のUPDATEはスキップする。
// （短時間の連続リロード・タブ再フォーカス等で毎回書き込みが走るのを防ぐ）
const SLIDING_WINDOW_THROTTLE_MS = 5 * 60 * 1000 // 5分

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    res.status(405).json({ error: 'Method Not Allowed' })
    return
  }

  const { deviceId } = req.body || {}

  if (typeof deviceId !== 'string' || !UUID_RE.test(deviceId)) {
    res.status(400).json({ ok: false, reason: 'invalid_request', error: '不正なリクエストです' })
    return
  }

  const SUPABASE_URL = process.env.SUPABASE_URL
  const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY

  if (!SUPABASE_URL || !SERVICE_KEY) {
    console.error('SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY が未設定です')
    res.status(500).json({ ok: false, reason: 'server_error', error: 'サーバー設定エラーが発生しました' })
    return
  }

  const supabase = createClient(SUPABASE_URL, SERVICE_KEY)

  // 拒否レスポンスを reason 付きで返す共通ヘルパー
  const reject = (status, reason, message) => {
    res.status(status).json({ ok: false, reason, error: message })
  }

  try {
    // 1. devices + members + auth_role を1クエリで取得（往復回数の削減）
    const { data: device, error: deviceErr } = await supabase
      .from('devices')
      .select(
        `id, member_id, status, expires_at, last_seen_at,
         members!devices_member_id_fkey(
           id, name, status,
           auth_role!auth_role_member_id_fkey(role)
         )`
      )
      .eq('id', deviceId)
      .maybeSingle()

    if (deviceErr) {
      console.error('devices取得エラー:', deviceErr)
      reject(500, 'server_error', 'サーバーエラーが発生しました')
      return
    }

    if (!device) {
      reject(404, 'not_found', '端末情報が見つかりません')
      return
    }

    // 2. 端末ステータスのチェック（pending/revoked）
    if (device.status === 'pending') {
      reject(403, 'pending', '端末が承認待ちです。管理者の承認をお待ちください')
      return
    }
    if (device.status === 'revoked') {
      reject(403, 'revoked', 'この端末は無効化されています。再度ログインしてください')
      return
    }
    // ここまで来れば status === 'approved' のはず

    // 3. 有効期限チェック（sliding windowの期限切れ）
    if (!device.expires_at || new Date(device.expires_at).getTime() <= Date.now()) {
      reject(403, 'expired', '端末の有効期限が切れています。再度ログインしてください')
      return
    }

    // 4. members.status のチェック（ネストselectの結果から。member自体が無ければ
    //    FK制約上ありえないが、念のためチェックしておく）
    const member = device.members
    if (!member || member.status === '無効') {
      reject(403, 'member_disabled', 'アカウントが無効化されています')
      return
    }

    // 5. auth_role の存在チェック（削除済み = ログイン権限自体が無い）
    // 1対1想定だが、PostgRESTの型（配列 or オブジェクト）どちらで返っても
    // 対応できるようにしておく
    const authRoleRaw = member.auth_role
    const authRole = Array.isArray(authRoleRaw) ? authRoleRaw[0] : authRoleRaw

    if (!authRole) {
      reject(403, 'account_deleted', 'アカウントが削除されています')
      return
    }

    // 6. sliding windowの延長 + last_seen_at/user_agent更新
    //    直近 SLIDING_WINDOW_THROTTLE_MS 以内に更新済みならスキップ
    //    （無駄なUPDATE往復・書き込みの削減。有効期限自体は十分に長い運用なので
    //      多少の間引きをしても実質的な影響はない）
    const userAgent = req.headers['user-agent'] || null
    const lastSeenMs = device.last_seen_at ? new Date(device.last_seen_at).getTime() : 0
    const shouldUpdate = Date.now() - lastSeenMs > SLIDING_WINDOW_THROTTLE_MS

    if (shouldUpdate) {
      const { error: updateErr } = await supabase
        .from('devices')
        .update({
          expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
          last_seen_at: new Date().toISOString(),
          user_agent: userAgent,
        })
        .eq('id', deviceId)

      if (updateErr) {
        // 延長更新に失敗しても、今回のアクセス自体は許可する（ログレベルの問題として扱う）
        console.error('devices更新(sliding window)エラー:', updateErr)
      }
    }

    // 7. セッションCookie発行（以降は requireAuth によるCookie認証に乗る）
    await issueSession(res, authRole.role, device.member_id)

    res.status(200).json({
      ok: true,
      memberId: device.member_id,
      memberName: member.name,
      role: authRole.role,
    })
  } catch (e) {
    console.error(e)
    reject(500, 'server_error', 'サーバーエラーが発生しました')
  }
}