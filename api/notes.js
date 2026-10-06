import { createClient } from '@supabase/supabase-js';

// 2단계 서버 함수: 학습용 Supabase 테이블 vault_notes에서 가상 메모를 읽습니다.
// SUPABASE_URL과 서버 전용 SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽고,
// 키 값을 응답·로그·브라우저 파일에 넣지 않습니다.
// 남은 약점: 3단계 전까지 이 주소는 로그인 없이 누구나 부를 수 있습니다.
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'GET만 받습니다.' });
  }
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) {
    console.error('notes: 서버 환경변수가 설정되지 않았습니다.');
    return res.status(500).json({ error: '서버 설정이 아직 끝나지 않았습니다.' });
  }
  const supabase = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data, error } = await supabase
    .from('vault_notes')
    .select('title, content')
    .order('sort_order', { ascending: true });
  if (error) {
    console.error('notes: 자료를 읽지 못했습니다.', error.code ?? 'unknown');
    return res.status(502).json({ error: '자료를 읽지 못했습니다.' });
  }
  return res.status(200).json({ notes: data });
}
