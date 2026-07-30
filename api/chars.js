// Vercel Serverless Function: /api/chars
// ブラウザからはこのエンドポイントだけを叩く。Supabaseへのアクセスは
// ここ（サーバー側）でのみ行い、service_role キーはクライアントに一切渡さない。

module.exports = async (req, res) => {
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!SUPABASE_URL || !SERVICE_KEY) {
    res.status(500).json({ error: 'SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY が未設定です（Vercelの環境変数を確認してください）' });
    return;
  }

  try {
    const r = await fetch(
      `${SUPABASE_URL}/rest/v1/chars?select=name,yomi,img&order=yomi.asc`,
      {
        headers: {
          apikey: SERVICE_KEY,
          Authorization: `Bearer ${SERVICE_KEY}`
        }
      }
    );

    if (!r.ok) {
      const text = await r.text();
      res.status(r.status).json({ error: `Supabase error: ${text}` });
      return;
    }

    const data = await r.json();
    res.setHeader('Cache-Control', 's-maxage=60, stale-while-revalidate=300');
    res.status(200).json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};