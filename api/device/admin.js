// Vercel Serverless Function: /api/device/admin
// member_id=1 のユーザーだけが実行できる、端末の一覧取得・承認・無効化API。
//
// [権限判定について]
// auth_role.role の値に依存せず、要件通り「member_id === 1」そのもので判定する。
// （role='admin'のような値が別途あるかどうか未確認のため、要件を素直に実装）
//
// GET  /api/device/admin
//   → 端末一覧を返す（メンバー名・status・issued_at・expires_at・last_seen_at・user_agent等）
//
// POST /api/device/admin
//   body: { deviceId: uuid, action: 'approve' | 'revoke' }
//   → action='approve': 指定端末を承認(approved)にする。
//     approved_at・approved_by（実行した管理者のmember_id）を記録し、
//     expires_atを now()+30日 にリセットする（sliding windowの起点をここから始める）
//   → action='revoke': 指定端末のレコードをdevicesテーブルから完全に削除する
//     （statusを'revoked'にするのではなく行自体を消す。一覧・DBから消したい、
//      という要件のため。削除された端末でverifyを叩いた場合はnot_foundとして
//      扱われ、フロント側は保存済みdeviceIdを破棄してログイン画面に戻る）
//
// [モジュール形式] chars.js / login.js と同じ CommonJS

const { createClient } = require('@supabase/supabase-js')
const { requireAuth } = require('../_lib/auth')

const ADMIN_MEMBER_ID = 1

module.exports = async (req, res) => {
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST')
    res.status(405).json({ error: 'Method Not Allowed' })
    return
  }

  // ログイン済みであることを確認（role不問。member_idでの判定は下で行う）
  const auth = await requireAuth(req, res, null)
  if (!auth) return // requireAuth内で401/403レスポンス済み

  // 要件通り、role値ではなく member_id === 1 そのもので管理者権限を判定
  if (auth.memberId !== ADMIN_MEMBER_ID) {
    res.status(403).json({ error: '権限がありません' })
    return
  }

  const SUPABASE_URL = process.env.SUPABASE_URL
  const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY

  if (!SUPABASE_URL || !SERVICE_KEY) {
    console.error('SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY が未設定です')
    res.status(500).json({ error: 'サーバー設定エラーが発生しました' })
    return
  }

  const supabase = createClient(SUPABASE_URL, SERVICE_KEY)

  if (req.method === 'GET') {
    try {
      // devices.member_id -> members.id のFK（devices_member_id_fkey）を使って
      // メンバー名を一緒に取得する（PostgRESTのネスト select）
      const { data, error } = await supabase
        .from('devices')
        .select(
          'id, member_id, status, issued_at, expires_at, approved_at, approved_by, last_seen_at, user_agent, members!devices_member_id_fkey(name)'
        )
        .order('status', { ascending: true }) // pending が先頭に来やすいよう文字列順（pending<approved<revoked）
        .order('issued_at', { ascending: false })

      if (error) {
        console.error('devices一覧取得エラー:', error)
        res.status(500).json({ error: 'データの取得に失敗しました' })
        return
      }

      // members(name) のネスト結果をフラットな memberName に整形して返す
      const devices = data.map((row) => ({
        id: row.id,
        memberId: row.member_id,
        memberName: row.members ? row.members.name : null,
        status: row.status,
        issuedAt: row.issued_at,
        expiresAt: row.expires_at,
        approvedAt: row.approved_at,
        approvedBy: row.approved_by,
        lastSeenAt: row.last_seen_at,
        userAgent: row.user_agent,
      }))

      res.status(200).json({ ok: true, devices })
    } catch (e) {
      console.error(e)
      res.status(500).json({ error: 'サーバーエラーが発生しました' })
    }
    return
  }

  // ---- POST: 承認 / 無効化 ----
  const { deviceId, action } = req.body || {}

  if (typeof deviceId !== 'string' || (action !== 'approve' && action !== 'revoke')) {
    res.status(400).json({ error: '不正なリクエストです' })
    return
  }

  try {
    // 対象端末の存在確認
    const { data: device, error: fetchErr } = await supabase
      .from('devices')
      .select('id')
      .eq('id', deviceId)
      .maybeSingle()

    if (fetchErr) {
      console.error('devices取得エラー:', fetchErr)
      res.status(500).json({ error: 'サーバーエラーが発生しました' })
      return
    }

    if (!device) {
      res.status(404).json({ error: '端末情報が見つかりません' })
      return
    }

    // revoke（無効化）の場合は、statusを立てるのではなく行自体をDBから削除する。
    // これにより一覧（GET）にも二度と出てこなくなる。
    // 参考: verify.jsは行が存在しなければ status==='revoked' 判定より先に
    //       「not_found（端末情報が見つかりません）」で弾かれるため、
    //       挙動としては引き続き安全（保存済みdeviceIdは破棄されログイン画面に戻る）。
    if (action === 'revoke') {
      const { error: deleteErr } = await supabase
        .from('devices')
        .delete()
        .eq('id', deviceId)

      if (deleteErr) {
        console.error('devices削除エラー:', deleteErr)
        res.status(500).json({ error: '削除に失敗しました' })
        return
      }

      res.status(200).json({ ok: true, deleted: true, deviceId })
      return
    }

    // ---- approve（承認） ----
    const updatePayload = {
      status: 'approved',
      approved_at: new Date().toISOString(),
      approved_by: auth.memberId,
      // 承認したタイミングを sliding window の起点とする
      expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
    }

    const { data: updated, error: updateErr } = await supabase
      .from('devices')
      .update(updatePayload)
      .eq('id', deviceId)
      .select(
        'id, member_id, status, issued_at, expires_at, approved_at, approved_by, last_seen_at, user_agent'
      )
      .single()

    if (updateErr) {
      console.error('devices更新エラー:', updateErr)
      res.status(500).json({ error: '更新に失敗しました' })
      return
    }

    res.status(200).json({
      ok: true,
      device: {
        id: updated.id,
        memberId: updated.member_id,
        status: updated.status,
        issuedAt: updated.issued_at,
        expiresAt: updated.expires_at,
        approvedAt: updated.approved_at,
        approvedBy: updated.approved_by,
        lastSeenAt: updated.last_seen_at,
        userAgent: updated.user_agent,
      },
    })
  } catch (e) {
    console.error(e)
    res.status(500).json({ error: 'サーバーエラーが発生しました' })
  }
}