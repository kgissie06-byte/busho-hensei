// Vercel Serverless Function: /api/login
// member_id + パスワードで認証し、成功したら ./_lib/auth.js の issueSession で
// JWT入りCookieを発行する（このアプリ専用。別アプリのauth.jsとは独立）。
//
// [事前準備]
// ・package.json に依存を追加: bcryptjs, jose, cookie, @supabase/supabase-js
// ・環境変数 JWT_SECRET を Vercel に設定（このアプリ専用の値。使い回さない）
//
// [前提/要確認]
// auth_role.password のハッシュ方式が不明だったため、Node/Vercelで最も一般的な
// bcryptjs を前提に実装しています。もし実際に別方式（argon2等）で発行されている
// 場合は、下記の bcrypt.compare(...) の1行だけを該当ライブラリの照合関数に
// 差し替えれば、他の処理はそのまま使えます。
//
// [セキュリティ方針]
// ・IDが存在しない場合とパスワード不一致の場合で、レスポンスを変えない
//   （IDの存在有無を外部から探索されるのを防ぐため）
// ・members.status が「無効」、または auth_role が存在しない（アカウント削除済み）
//   場合はログインさせない
// ・エラー詳細はサーバーログにのみ出し、クライアントには汎用メッセージのみ返す

const bcrypt = require('bcryptjs')
const { createClient } = require('@supabase/supabase-js')
const { issueSession } = require('./_lib/auth')

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    res.status(405).json({ error: 'Method Not Allowed' })
    return
  }

  const { memberId, password } = req.body || {}

  // 入力バリデーション（型・存在チェックのみ。中身の意味的な検証はDB照合で行う）
  const memberIdNum = Number(memberId)
  if (!Number.isInteger(memberIdNum) || typeof password !== 'string' || !password) {
    res.status(400).json({ error: 'IDとパスワードを入力してください' })
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

  // 共通の失敗レスポンス（存在しないIDと不一致パスワードを区別しない）
  const invalidCredentials = () => {
    res.status(401).json({ error: 'IDまたはパスワードが正しくありません' })
  }

  try {
    // members側の在籍状況（有効/無効）を確認
    const { data: member, error: memberErr } = await supabase
      .from('members')
      .select('id, name, status')
      .eq('id', memberIdNum)
      .maybeSingle()

    if (memberErr) {
      console.error('members取得エラー:', memberErr)
      res.status(500).json({ error: 'サーバーエラーが発生しました' })
      return
    }

    // メンバー自体が存在しない、または無効化されている
    if (!member || member.status === '無効') {
      invalidCredentials()
      return
    }

    // auth_role（パスワード・ロール）を取得
    const { data: authRole, error: authErr } = await supabase
      .from('auth_role')
      .select('role, password')
      .eq('member_id', memberIdNum)
      .maybeSingle()

    if (authErr) {
      console.error('auth_role取得エラー:', authErr)
      res.status(500).json({ error: 'サーバーエラーが発生しました' })
      return
    }

    // auth_roleが存在しない = アカウント（権限情報）が削除済み
    if (!authRole || !authRole.password) {
      invalidCredentials()
      return
    }

    const match = await bcrypt.compare(password, authRole.password)
    if (!match) {
      invalidCredentials()
      return
    }

    // 認証成功 → セッション発行（Cookieにセット）
    await issueSession(res, authRole.role, memberIdNum)

    res.status(200).json({
      ok: true,
      memberId: memberIdNum,
      memberName: member.name,
      role: authRole.role,
    })
  } catch (e) {
    console.error(e)
    res.status(500).json({ error: 'サーバーエラーが発生しました' })
  }
}