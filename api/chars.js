// Vercel Serverless Function: /api/chars
// ブラウザからはこのエンドポイントだけを叩く。Supabaseへのアクセスは
// ここ（サーバー側）でのみ行い、service_role キーはクライアントに一切渡さない。
//
// [SQLインジェクション対策について]
// このエンドポイントは固定のPostgRESTクエリ（select/orderのみ）しか発行しておらず、
// リクエストからのパラメータを一切クエリ文字列に組み込んでいないため、
// 現状はSQLインジェクションの入力経路自体が存在しない。
// 今後「名前で検索」等のフィルタ機能を追加する場合は、
//   1) req.query の値を絶対に文字列結合でURL/SQLに埋め込まない
//   2) PostgRESTのフィルタ演算子（?name=eq.xxx など）を使う場合も、
//      値は必ず encodeURIComponent() で安全にエンコードした上でホワイトリスト
//      的にバリデーション（型・長さ・許容文字）してから使う
//   3) 可能なら supabase-js の `.eq()` / `.ilike()` 等のビルダー経由で渡し、
//      生のSQL文字列やPostgRESTクエリ文字列を手組みしない
// というルールを守ること。

module.exports = async (req, res) => {
  // GET以外は拒否（このAPIは参照専用）
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    res.status(405).json({ error: 'Method Not Allowed' });
    return;
  }

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!SUPABASE_URL || !SERVICE_KEY) {
    console.error('SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY が未設定です');
    res.status(500).json({ error: 'サーバー設定エラーが発生しました' });
    return;
  }

  try {
    // クエリはリクエスト由来の値を一切含まない固定文字列
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
      // Supabase側の詳細なエラー内容はサーバーログにのみ出し、
      // クライアントには内部実装の手がかりを与えない汎用メッセージのみ返す
      const text = await r.text().catch(() => '');
      console.error(`Supabase error (${r.status}):`, text);
      res.status(502).json({ error: 'データの取得に失敗しました' });
      return;
    }

    const data = await r.json();
    res.setHeader('Cache-Control', 's-maxage=60, stale-while-revalidate=300');
    res.status(200).json(data);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
};