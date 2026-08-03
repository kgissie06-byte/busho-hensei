// このアプリ専用のセッション管理ヘルパー（CommonJS版）
// 別アプリで運用されている auth.js と同じ設計思想（JWT + httpOnly Cookie、
// invalidate_beforeによる強制ログアウト）を、このアプリ（chars.js等と同じ
// CommonJS形式）向けに移植したもの。
//
// 依存パッケージ: jose, cookie, @supabase/supabase-js
// 必須環境変数: JWT_SECRET（このアプリ専用の秘密鍵。別アプリとは分けること推奨）

const { SignJWT, jwtVerify } = require('jose')
const { serialize, parse } = require('cookie')

const secret = new TextEncoder().encode(process.env.JWT_SECRET)

const COOKIE_NAME = 'session'
const COOKIE_MAX_AGE = 60 * 60 * 12 // 12時間

/** ログイン成功後にJWTを発行してCookieにセット */
async function issueSession(res, role, memberId) {
  const token = await new SignJWT({ role, memberId })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('12h')
    .sign(secret)

  res.setHeader('Set-Cookie', serialize(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: COOKIE_MAX_AGE,
  }))
}

/** Cookieのセッションを破棄 */
function clearSession(res) {
  res.setHeader('Set-Cookie', serialize(COOKIE_NAME, '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 0,
  }))
}

/**
 * 認証チェック。認証OKなら { role, memberId } を返す。
 * NGなら自動でエラーレスポンスを返して null を返す。
 *
 * @param {object} req
 * @param {object} res
 * @param {'admin'|'user'|null} requiredRole - nullなら認証済みであれば誰でもOK
 */
async function requireAuth(req, res, requiredRole = null) {
  const cookies = parse(req.headers.cookie || '')
  const token = cookies[COOKIE_NAME]

  if (!token) {
    res.status(401).json({ error: '認証が必要です' })
    return null
  }

  let payload
  try {
    const verified = await jwtVerify(token, secret)
    payload = verified.payload
  } catch {
    res.status(401).json({ error: 'セッションが無効です。再ログインしてください' })
    return null
  }

  // パスワード変更・アカウント削除後の古いセッションを弾く
  if (payload.memberId) {
    const { createClient } = require('@supabase/supabase-js')
    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_ROLE_KEY
    )
    const { data } = await supabase
      .from('auth_role')
      .select('invalidate_before')
      .eq('member_id', payload.memberId)
      .maybeSingle()

    if (!data) {
      res.status(401).json({ error: 'アカウントが削除されました。再ログインしてください' })
      return null
    }

    if (data.invalidate_before) {
      const invalidateBefore = new Date(data.invalidate_before).getTime() / 1000
      if (payload.iat < invalidateBefore) {
        res.status(401).json({ error: 'パスワードが変更されました。再ログインしてください' })
        return null
      }
    }
  }

  if (requiredRole && payload.role !== requiredRole) {
    res.status(403).json({ error: '権限がありません' })
    return null
  }

  return { role: payload.role, memberId: payload.memberId || null }
}

module.exports = { issueSession, clearSession, requireAuth }