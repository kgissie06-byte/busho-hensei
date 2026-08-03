// Vercel Serverless Function: /api/device/verify
// クライアント側(localStorage等)に保存されたdeviceId(UUID)を検証するAPI。
// ログイン画面を経由せず、このAPIだけで「実質のログイン」を完結させる想定。
//
// [フロー]
// 1. devices テーブルを deviceId で検索
// 2. status / expires_at / members.status / auth_role の有無を順番にチェック
// 3. 全て問題なければ、
//    - expires_at を now()+30日に更新（sliding window）
//    - last_seen_at・user_agent を更新
//    - ./_lib/auth.js の issueSession でJWTセッションCookieを発行
//      （以降は他のAPIで requireAuth によるCookie認証がそのまま使える）
// 4. どこかの段階で拒否する場合は、理由(reason)付きで401/403を返す
//    ※ login.jsとは違い、こちらは「IDの存在を隠す」必要がないので
//      reasonを具体的に返してフロント側で適切な画面分岐をできるようにする
//      （例: pending→承認待ち画面、revoked/expired→ログイン画面に戻す 等）
//
// [モジュール形式] chars.js / login.js と同じ CommonJS

const { createClient } = require('@supabase/supabase-js')
const { issueSession } = require('../_lib/auth')

// UUID形式の簡易バリデーション（v4に限定せず、ハイフン区切りの16進形式であれば許容）
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

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
    // 1. devices テーブルから該当端末を検索
    const { data: device, error: deviceErr } = await supabase
      .from('devices')
      .select('id, member_id, status, expires_at')
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

    // 4. members.status のチェック（無効化はdevicesとは別概念）
    const { data: member, error: memberErr } = await supabase
      .from('members')
      .select('id, name, status')
      .eq('id', device.member_id)
      .maybeSingle()

    if (memberErr) {
      console.error('members取得エラー:', memberErr)
      reject(500, 'server_error', 'サーバーエラーが発生しました')
      return
    }

    if (!member || member.status === '無効') {
      reject(403, 'member_disabled', 'アカウントが無効化されています')
      return
    }

    // 5. auth_role の存在チェック（削除済み = ログイン権限自体が無い）
    const { data: authRole, error: authErr } = await supabase
      .from('auth_role')
      .select('role')
      .eq('member_id', device.member_id)
      .maybeSingle()

    if (authErr) {
      console.error('auth_role取得エラー:', authErr)
      reject(500, 'server_error', 'サーバーエラーが発生しました')
      return
    }

    if (!authRole) {
      reject(403, 'account_deleted', 'アカウントが削除されています')
      return
    }

    // 6. 全チェック通過 → sliding windowで有効期限を延長 + last_seen_at/user_agent更新
    const userAgent = req.headers['user-agent'] || null
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