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

const { createClient } = require('@supabase/supabase-js')
const { requireAuth } = require('../_lib/auth')

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