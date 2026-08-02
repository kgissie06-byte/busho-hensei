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

// ===== Cloudinary画像の帯域最適化 =====
// クライアント側(140px角)で表示するのに元画像(数百KB〜数MB)をそのまま
// 配信すると無駄に帯域を消費する（Cloudinaryのプラン上限＝「パンク」の原因）。
// f_auto,q_auto はブラウザ対応フォーマットへの自動変換・知覚的に無劣化な
// 範囲での自動圧縮なので、見た目の粗さはほぼ変えずにファイルサイズだけ削れる。
// w_,h_,c_fill で表示サイズ以上の解像度を送らないようにする。
function optimizeCloudinaryUrl(url, size = 280) {
  if (typeof url !== 'string' || !url) return url;
  if (!/(^|\.)res\.cloudinary\.com\//.test(url)) return url; // cloudinary以外のURLは無変換
  const marker = '/upload/';
  const idx = url.indexOf(marker);
  if (idx === -1) return url; // 想定外の形式のURLはそのまま返す（壊さない）
  const insertPos = idx + marker.length;
  return url.slice(0, insertPos)
    + `f_auto,q_auto,w_${size},h_${size},c_fill/`
    + url.slice(insertPos);
}

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

    // 一覧カード表示(140px角、Retina想定で280px)を想定して最適化。
    // 画質はq_autoが自動で維持するので、明示的に荒くする処理ではない。
    const optimized = data.map(row => ({
      ...row,
      img: optimizeCloudinaryUrl(row.img)
    }));

    res.setHeader('Cache-Control', 's-maxage=60, stale-while-revalidate=300');
    res.status(200).json(optimized);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
};