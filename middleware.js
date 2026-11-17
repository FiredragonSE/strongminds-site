import { next } from '@vercel/functions';

export const config = {
  matcher: ['/reporting', '/reporting/:path*'],
};

const HEADERS = { 'X-Robots-Tag': 'noindex, nofollow, noarchive', 'Cache-Control': 'private, no-store' };

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export default function middleware(request) {
  const user = process.env.REPORTING_USER;
  const pass = process.env.REPORTING_PASSWORD;
  const unauthorized = () =>
    new Response('Authentication required', {
      status: 401,
      headers: { ...HEADERS, 'WWW-Authenticate': 'Basic realm="Reporting", charset="UTF-8"' },
    });
  if (!user || !pass) return unauthorized(); // fail closed if not configured
  const header = request.headers.get('authorization') || '';
  if (!header.startsWith('Basic ')) return unauthorized();
  let decoded = '';
  try {
    const bin = atob(header.slice(6));
    decoded = new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
  } catch {
    return unauthorized();
  }
  const i = decoded.indexOf(':');
  if (i < 0) return unauthorized();
  if (safeEqual(decoded.slice(0, i), user) && safeEqual(decoded.slice(i + 1), pass)) {
    return next({ headers: HEADERS });
  }
  return unauthorized();
}
