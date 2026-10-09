// Porteiro do site (Vercel Routing Middleware): enquanto não for a hora, quem abre uma página do Bup vai para /join.
// Quando launch_at chega (ou o admin libera), o site abre sozinho, sem novo deploy.
// Sem nada configurado no /admin, o site continua travado (modo pré-lançamento).
import { neon } from '@neondatabase/serverless';

// O matcher precisa ser uma lista literal (a Vercel lê estaticamente; não aceita spread nem variáveis).
export const config = {
  matcher: [
    '/', '/index', '/expressoes', '/como-funciona', '/faq',
    '/privacidade', '/termos', '/conta', '/configuracoes', '/conversar',
    '/index.html', '/expressoes.html', '/como-funciona.html', '/faq.html', '/privacidade.html',
    '/termos.html', '/conta.html', '/configuracoes.html', '/conversar.html',
  ],
};

const TTL = 10000; // consulta o banco no máximo a cada 10 s por instância
let cache = null, sql;
const state = async () => {
  if (cache && Date.now() - cache.at < TTL) return cache;
  try {
    sql ||= neon(process.env.DATABASE_URL);
    const r = await sql`SELECT launch_at, open_now FROM launch WHERE id = 1`;
    cache = { at: Date.now(), openNow: !!(r[0] && r[0].open_now), ms: r[0] && r[0].launch_at ? new Date(r[0].launch_at).getTime() : null };
  } catch (e) {
    // banco fora do ar ou tabela ainda não criada: mantém o último estado conhecido (ou travado)
    cache = cache ? { ...cache, at: Date.now() - TTL + 3000 } : { at: Date.now() - TTL + 3000, openNow: false, ms: null };
  }
  return cache;
};

// HMAC-SHA256 em base64url (igual ao createHmac(...).digest('base64url') do Node)
const enc = new TextEncoder();
const hmac = async (secret, msg) => {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  let b = ''; for (const x of new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(msg)))) b += String.fromCharCode(x);
  return btoa(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const same = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
const cookie = (req, name) => { const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)')); return m ? m[1] : ''; };
const isAdmin = async (req) => { const v = cookie(req, 'bup_preview'); return !!(v && process.env.ADMIN_KEY && same(v, await hmac(process.env.ADMIN_KEY, 'bup-preview'))); };
const isLogged = async (req) => {
  const m = cookie(req, 'bup_session').match(/^(\d+)\.(\d+)\.([\w-]+)$/);
  return !!(m && process.env.AUTH_SECRET && +m[2] > Date.now() && same(m[3], await hmac(process.env.AUTH_SECRET, m[1] + '.' + m[2])));
};
const FREE_OF_LOGIN = /^\/(conversar|termos|privacidade)(\.html)?\/?$/; // login e textos legais

export default async function middleware(request) {
  const s = await state();
  const open = s.openNow || (s.ms !== null && Date.now() >= s.ms);
  if (!open && !(await isAdmin(request))) return Response.redirect(new URL('/join', request.url), 307);
  const path = new URL(request.url).pathname;
  if (!FREE_OF_LOGIN.test(path) && !(await isLogged(request))) return Response.redirect(new URL('/conversar', request.url), 307);
  return new Response(null, { headers: { 'x-middleware-next': '1' } }); // equivale a next()
}
