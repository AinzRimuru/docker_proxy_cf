/**
 * Cloudflare Worker — Docker Hub pull-only reverse proxy
 *
 * 通过你自己的 Worker 域名拉取 Docker Hub 镜像：
 *   docker pull <worker-domain>/library/nginx | <domain>/nginx | <domain>/user/repo:tag
 * 也可作为 registry-mirror 配置后直接 docker pull nginx。
 *
 * 鉴权 / 限流 / 账号池：
 *  - 账号池（D1，推荐）：绑定 D1（env.DB），accounts 表存多个 Docker Hub 账号。Worker 按 last_used
 *    轮询选号；某账号触发 429（额度耗尽）即标记 rate_limited_until=now+6h，冷却期内跳过、自动换号。
 *    所有账号冷却时返回 429。
 *  - 单账号回退：未绑定 D1 时用 DH_USERNAME / DH_PASSWORD（无冷却轮换）。
 *  - PROXY_TOKEN_KEY：token 保护。/token 只签发 proxy token，真实账号 token 仅 Worker 内部使用。
 *  - ACCESS_KEY（可选）：访问控制（docker login 密码位）。
 *
 * 其它：blob 透传 307 到 CDN；官方镜像自动补 library/；仅 pull（GET/HEAD/OPTIONS）。
 */

const REGISTRY_HOST = 'registry-1.docker.io';
const AUTH_HOST = 'auth.docker.io';
const AUTH_SERVICE = 'registry.docker.io';
const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const REDIRECT_PREFIX = 'redirect_to_'; // 上游 3xx 改写前缀：CDN 跳转改写回本代理，由本代理回源
const PROXY_TOKEN_TTL = 3600; // proxy token 有效期（秒）
const COOLDOWN_MS = 6 * 60 * 60 * 1000; // 账号触发 429 后冷却 6 小时

// 转发到上游时要丢弃的 hop-by-hop / CF 注入请求头（fetch 会按 URL 自动设置 Host）。
const DROP_REQ_HEADERS = [
  'host',
  'cf-connecting-ip',
  'cf-ipcountry',
  'cf-ipcity',
  'cf-iplongitude',
  'cf-iplatitude',
  'cf-ray',
  'cf-visitor',
  'cf-worker',
  'cf-pw-cache-status',
  'x-forwarded-for',
  'x-forwarded-proto',
  'x-real-ip',
  'cdn-loop',
  'via',
];

// 账号 token 缓存：`username|scope` -> { token, expiresAt }
const tokenCache = new Map();
const TOKEN_CACHE_MAX = 1000;

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env);
    } catch (err) {
      return new Response(`proxy error: ${err && err.message ? err.message : err}`, {
        status: 502,
        headers: corsBase(),
      });
    }
  },
};

async function handleRequest(request, env) {
  const url = new URL(request.url);

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsPreflight() });
  }

  if (!ALLOWED_METHODS.has(request.method)) {
    return new Response('method not allowed (pull-only proxy)', {
      status: 405,
      headers: { allow: 'GET, HEAD, OPTIONS', ...corsBase() },
    });
  }

  // CDN 回源：/redirect_to_<host>/<path> → 代理到 host（blob 跳转经此回源，客户端不直连 CDN）
  if (url.pathname.startsWith('/' + REDIRECT_PREFIX)) {
    return handleCdnRedirect(request, url, env);
  }

  if (url.pathname === '/token' || url.pathname.startsWith('/token/')) {
    return proxyAuth(request, url, env);
  }

  if (url.pathname === '/v2' || url.pathname === '/v2/' || url.pathname.startsWith('/v2/')) {
    return proxyRegistry(request, url, env);
  }

  if (url.pathname === '/') {
    return htmlResponse(infoPage(url.host));
  }

  return new Response('not found', { status: 404, headers: corsBase() });
}

/** /token：保护模式下签发 proxy token；否则转发 auth.docker.io。 */
async function proxyAuth(request, url, env) {
  if (env && env.PROXY_TOKEN_KEY) {
    if (env.ACCESS_KEY && extractAccessKey(request, url) !== env.ACCESS_KEY) {
      return jsonError(401, 'UNAUTHORIZED', 'access key required');
    }
    const scope = url.searchParams.get('scope') || '';
    const now = Math.floor(Date.now() / 1000);
    const token = await signProxyToken(env, { scope, iat: now, exp: now + PROXY_TOKEN_TTL });
    const body = {
      token,
      access_token: token,
      expires_in: PROXY_TOKEN_TTL,
      issued_at: new Date(now * 1000).toISOString(),
    };
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json', ...corsBase() },
    });
  }

  const upstream = `https://${AUTH_HOST}${url.pathname}${url.search}`;
  const headers = buildUpstreamHeaders(request);
  if (env && env.DH_USERNAME && env.DH_PASSWORD) {
    headers.set('Authorization', 'Basic ' + btoa(`${env.DH_USERNAME}:${env.DH_PASSWORD}`));
  }
  const res = await fetch(upstream, { method: request.method, headers, redirect: 'follow' });
  return passthrough(res);
}

/** /v2/...：保护模式下校验 proxy token；用账号池鉴权上游（429 自动冷却换号）。 */
async function proxyRegistry(request, url, env) {
  const originalPath = url.pathname;
  const upstreamPath = rewriteOfficialImage(originalPath);
  const upstream = `https://${REGISTRY_HOST}${upstreamPath}${url.search}`;
  // 客户端侧 scope（原始路径）与上游侧 scope（改写后路径）解耦。
  const proxyScope = getScopeForPath(originalPath);
  const accountScope = getScopeForPath(upstreamPath);
  const protectedMode = !!(env && env.PROXY_TOKEN_KEY);

  if (protectedMode) {
    const bearer = (request.headers.get('authorization') || '').replace(/^Bearer\s+/i, '').trim();
    const payload = await verifyProxyToken(env, bearer);
    const allowed = payload && (payload.scope === proxyScope || proxyScope === '');
    if (!allowed) return unauthorizedResponse(url, proxyScope);
  }

  const headers = buildUpstreamHeaders(request);
  const useAccount = accountConfigured(env) && accountScope !== null;

  let res;
  if (useAccount) {
    res = await fetchWithAccountPool(env, upstream, request.method, headers, accountScope);
  } else {
    res = await fetch(upstream, { method: request.method, headers, redirect: 'manual' });
  }

  return rewriteRegistryResponse(res, url);
}

/** 是否配置了账号源（D1 或单账号） */
function accountConfigured(env) {
  return !!(env && (env.DB || (env.DH_USERNAME && env.DH_PASSWORD)));
}

/** 由请求路径推断 token scope；null 表示不需要鉴权。 */
function getScopeForPath(pathname) {
  if (pathname === '/v2' || pathname === '/v2/') return '';
  const m = pathname.match(/^\/v2\/(.+)\/(?:manifests|blobs|tags)\//);
  return m ? `repository:${m[1]}:pull` : null;
}

/** 取可用账号（rate_limited_until < now），按 last_used 轮询。D1 优先，空则回退单账号。 */
async function getAvailableAccounts(env) {
  if (env && env.DB) {
    try {
      const now = Date.now();
      const { results } = await env.DB.prepare(
        'SELECT username, password FROM accounts WHERE enabled=1 AND (rate_limited_until IS NULL OR rate_limited_until < ?1) ORDER BY last_used ASC'
      )
        .bind(now)
        .all();
      if (results && results.length) return results;
    } catch (e) {
      // D1 查询失败则回退单账号
    }
  }
  if (env && env.DH_USERNAME && env.DH_PASSWORD) {
    return [{ username: env.DH_USERNAME, password: env.DH_PASSWORD }];
  }
  return [];
}

/** 用指定账号向 auth.docker.io 换取 scope 的 token（按 账号+scope 缓存）。 */
async function mintToken(env, account, scope) {
  const key = `${account.username}|${scope}`;
  const now = Date.now();
  const cached = tokenCache.get(key);
  if (cached && cached.expiresAt > now) return cached.token;

  const params = new URLSearchParams();
  params.set('service', AUTH_SERVICE);
  if (scope) params.set('scope', scope);

  const res = await fetch(`https://${AUTH_HOST}/token?${params.toString()}`, {
    headers: { Authorization: 'Basic ' + btoa(`${account.username}:${account.password}`) },
  });
  if (!res.ok) throw new Error(`auth.docker.io token request failed: ${res.status}`);
  const data = await res.json();
  const token = data.token || data.access_token;
  if (!token) throw new Error('auth.docker.io returned no token');

  if (tokenCache.size > TOKEN_CACHE_MAX) tokenCache.clear();
  const expiresIn = Number(data.expires_in) || 300;
  tokenCache.set(key, { token, expiresAt: now + Math.max(60, expiresIn - 60) * 1000 });
  return token;
}

/** 用账号池依次尝试：取号→mint→上游；429 则冷却该号并换下一个；401(scope) 同号重试一次。 */
async function fetchWithAccountPool(env, upstream, method, headers, scope) {
  const accounts = await getAvailableAccounts(env);
  if (!accounts.length) return noAccountsResponse();

  for (const account of accounts) {
    let token;
    try {
      token = await mintToken(env, account, scope);
    } catch (e) {
      continue; // 签到失败，换下一个
    }
    headers.set('Authorization', 'Bearer ' + token);
    let res = await fetch(upstream, { method, headers, redirect: 'manual' });

    // 上游 401 多为 scope 不符（如 /v2/ ping）：按上游要求的 scope 同号重试一次
    if (res.status === 401) {
      const wwwAuth = res.headers.get('www-authenticate') || '';
      const m = wwwAuth.match(/scope="([^"]*)"/);
      const retryScope = m && m[1] ? m[1] : '';
      if (retryScope && retryScope !== scope) {
        try {
          res.body && res.body.cancel && (await res.body.cancel());
          token = await mintToken(env, account, retryScope);
          headers.set('Authorization', 'Bearer ' + token);
          res = await fetch(upstream, { method, headers, redirect: 'manual' });
        } catch (e) {}
      }
    }

    if (res.status === 429) {
      // 该账号额度耗尽：冷却并尝试下一个账号
      res.body && res.body.cancel && (await res.body.cancel());
      await coolDownAccount(env, account.username);
      continue;
    }

    // 成功（或非 429 的其它状态）：标记使用并返回
    await markUsed(env, account.username);
    return res;
  }
  // 所有账号均被限流
  return rateLimitedResponse();
}

/** 标记账号最近使用时间（D1，用于轮询）。必须 await，否则响应返回后写入会被取消。 */
function markUsed(env, username) {
  if (!env || !env.DB) return Promise.resolve();
  const now = Date.now();
  return env.DB.prepare('UPDATE accounts SET last_used=?1 WHERE username=?2')
    .bind(now, username)
    .run()
    .catch(() => {});
}

/** 账号触发 429：设冷却时间（now+6h）、计数+1、清缓存。D1 才持久化。 */
async function coolDownAccount(env, username) {
  for (const k of tokenCache.keys()) {
    if (k.startsWith(username + '|')) tokenCache.delete(k);
  }
  if (env && env.DB) {
    try {
      await env.DB.prepare(
        'UPDATE accounts SET rate_limited_until=?1, limited_count=limited_count+1 WHERE username=?2'
      )
        .bind(Date.now() + COOLDOWN_MS, username)
        .run();
    } catch (e) {}
  }
}

function noAccountsResponse() {
  return jsonError(503, 'UNAVAILABLE', 'no docker hub accounts available');
}

function rateLimitedResponse() {
  return jsonError(429, 'TOOMANYREQUESTS', 'all accounts rate limited, retry later', {
    'retry-after': String(Math.round(COOLDOWN_MS / 1000)),
  });
}

// ===== proxy token（JWT HS256，HMAC-SHA256）=====

function b64url(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlStr(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecodeToStr(b64u) {
  const b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - (b64.length % 4)) % 4;
  return atob(b64 + '='.repeat(pad));
}

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

async function signProxyToken(env, payload) {
  const key = await hmacKey(env.PROXY_TOKEN_KEY);
  const headerB64 = b64urlStr(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payloadB64 = b64urlStr(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signingInput));
  return `${signingInput}.${b64url(sig)}`;
}

async function verifyProxyToken(env, token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;
  const signingInput = `${headerB64}.${payloadB64}`;
  const key = await hmacKey(env.PROXY_TOKEN_KEY);
  const sigBin = b64urlDecodeToStr(sigB64);
  const sigBytes = new Uint8Array(sigBin.length);
  for (let i = 0; i < sigBin.length; i++) sigBytes[i] = sigBin.charCodeAt(i);
  let valid = false;
  try {
    valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(signingInput));
  } catch (e) {
    return null;
  }
  if (!valid) return null;
  let payload;
  try {
    payload = JSON.parse(b64urlDecodeToStr(payloadB64));
  } catch (e) {
    return null;
  }
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) return null;
  return payload;
}

function extractAccessKey(request, url) {
  const auth = request.headers.get('authorization') || '';
  const m = auth.match(/^Basic\s+(.+)$/i);
  if (m) {
    try {
      const decoded = atob(m[1]);
      const idx = decoded.indexOf(':');
      return idx >= 0 ? decoded.slice(idx + 1) : decoded;
    } catch (e) {}
  }
  return url.searchParams.get('key') || request.headers.get('x-access-key') || '';
}

function unauthorizedResponse(url, scope) {
  const params = [`realm="${url.origin}/token"`, `service="${AUTH_SERVICE}"`];
  if (scope) params.push(`scope="${scope}"`);
  return jsonError(401, 'UNAUTHORIZED', 'authentication required', {
    'www-authenticate': `Bearer ${params.join(',')}`,
    'docker-distribution-api-version': 'registry/2.0',
  });
}

function jsonError(status, code, message, extra = {}) {
  const body = JSON.stringify({ errors: [{ code, message }] });
  return new Response(body, {
    status,
    headers: { 'content-type': 'application/json', ...corsBase(), ...extra },
  });
}

// ===== 重定向改写（上游 CDN 跳转改写回本代理，由本代理回源；客户端不直连 CDN）=====

/** 仅允许 Docker 自有域名回源（防 SSRF / 被当开放代理）*/
function isAllowedUpstream(host) {
  return host.endsWith('.docker.com') || host.endsWith('.docker.io');
}

/** 解析 /redirect_to_<host>/<path> */
function parseRedirectPath(pathname) {
  const m = pathname.match(/^\/redirect_to_([^/]+)(\/.*)$/);
  if (!m) return null;
  return { host: m[1], path: m[2] };
}

/** 把上游 Location 改写为 <代理>/redirect_to_<host><path>?<query> */
function rewriteLocation(location, proxyOrigin) {
  try {
    const u = new URL(location);
    if (!isAllowedUpstream(u.hostname)) return null;
    return `${proxyOrigin}/${REDIRECT_PREFIX}${u.hostname}${u.pathname}${u.search}`;
  } catch (e) {
    return null;
  }
}

/** 处理 /redirect_to_<host>/...：回源到 host 并流式返回（blob 下载经此路径）*/
async function handleCdnRedirect(request, url, env) {
  const parsed = parseRedirectPath(url.pathname);
  if (!parsed || !isAllowedUpstream(parsed.host)) {
    return new Response('forbidden upstream', { status: 403, headers: corsBase() });
  }
  const upstream = `https://${parsed.host}${parsed.path}${url.search}`;
  const headers = buildUpstreamHeaders(request);
  let res;
  try {
    res = await fetch(upstream, { method: request.method, headers, redirect: 'manual' });
  } catch (e) {
    return new Response(`upstream error: ${e.message}`, { status: 502, headers: corsBase() });
  }
  const h = new Headers(res.headers);
  stripRevealingHeaders(h);
  // CDN 若再次跳转，继续改写
  if ([301, 302, 303, 307, 308].includes(res.status)) {
    const loc = h.get('location');
    if (loc) {
      const newLoc = rewriteLocation(loc, url.origin);
      if (newLoc) h.set('location', newLoc);
    }
  }
  applyCors(h);
  return new Response(res.body, { status: res.status, headers: h });
}

/**
 * Docker Hub 官方镜像存放在 library/ 命名空间下。客户端拉 <domain>/nginx 不会自动补 library/，
 * 这里把单段镜像名改写为 /v2/library/<name>/...。多段名与已是 library/ 的不变。
 */
function rewriteOfficialImage(pathname) {
  const m = pathname.match(/^\/v2\/([^/]+)\/(manifests|blobs|tags)\/(.*)$/);
  if (m && !m[1].includes('/')) {
    return `/v2/library/${m[1]}/${m[2]}/${m[3]}`;
  }
  return pathname;
}

// 响应中会暴露账号身份/额度的头，一律剥离（账号用户名可能即密码，绝不能外泄）。
const STRIP_RES_HEADERS = [
  'docker-ratelimit-source', // 上游会带出 token 所属账号用户名 —— 关键泄露点
  'ratelimit-limit',
  'ratelimit-remaining',
  'ratelimit-reset',
  'x-ratelimit-limit',
  'x-ratelimit-remaining',
  'x-ratelimit-reset',
];

function stripRevealingHeaders(headers) {
  for (const k of STRIP_RES_HEADERS) headers.delete(k);
  return headers;
}

/** 整理 registry 响应：剥除泄露头、改写 realm、补 v2 头、加 CORS。保留 content-length。 */
function rewriteRegistryResponse(res, url) {
  const headers = new Headers(res.headers);
  stripRevealingHeaders(headers);

  // 上游 3xx（如 blob 的 307 到 CDN）改写 Location，让客户端经本代理回源，而非直连 CDN
  if ([301, 302, 303, 307, 308].includes(res.status)) {
    const loc = headers.get('location');
    if (loc) {
      const newLoc = rewriteLocation(loc, url.origin);
      if (newLoc) headers.set('location', newLoc);
    }
  }

  const wwwAuth = headers.get('www-authenticate');
  if (wwwAuth) {
    const realm = `${url.origin}/token`;
    headers.set('www-authenticate', wwwAuth.replace(/realm="[^"]*"/i, `realm="${realm}"`));
  }
  if (!headers.has('docker-distribution-api-version')) {
    headers.set('docker-distribution-api-version', 'registry/2.0');
  }

  applyCors(headers);
  return new Response(res.body, { status: res.status, headers });
}

function passthrough(res) {
  const headers = new Headers(res.headers);
  stripRevealingHeaders(headers);
  applyCors(headers);
  return new Response(res.body, { status: res.status, headers });
}

function buildUpstreamHeaders(request) {
  const h = new Headers(request.headers);
  for (const key of DROP_REQ_HEADERS) h.delete(key);
  h.set('accept-encoding', 'identity');
  return h;
}

function corsBase() {
  return { 'access-control-allow-origin': '*', 'access-control-expose-headers': '*' };
}

function corsPreflight() {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, HEAD, OPTIONS',
    'access-control-allow-headers':
      'Authorization, Accept, Accept-Encoding, Range, Content-Type, Docker-Content-Digest, Docker-Distribution-API-Version',
    'access-control-expose-headers': '*',
    'access-control-max-age': '86400',
  };
}

function applyCors(headers) {
  headers.set('access-control-allow-origin', '*');
  headers.set('access-control-expose-headers', '*');
  return headers;
}

function htmlResponse(body) {
  return new Response(body, {
    headers: { 'content-type': 'text/html; charset=utf-8', ...corsBase() },
  });
}

function infoPage(host) {
  const examples = [
    `docker pull ${host}/library/nginx`,
    `docker pull ${host}/nginx`,
    `docker pull ${host}/user/repo:tag`,
  ].join('\n');
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Docker Hub Mirror</title>
<style>
  body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#0b1020;color:#e6e9f2;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .card{max-width:680px;width:100%}
  h1{font-size:1.6rem;margin:0 0 .4rem}
  p.sub{color:#9aa4bf;margin:0 0 1.4rem}
  pre{background:#11182e;border:1px solid #233056;border-radius:10px;padding:14px 16px;overflow:auto;line-height:1.6}
  code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  .tag{display:inline-block;background:#16336e;color:#9cc2ff;border-radius:999px;padding:2px 10px;font-size:.78rem;margin-bottom:1rem}
  .star{display:inline-flex;align-items:center;gap:7px;background:#24292f;color:#fff;text-decoration:none;padding:8px 14px;border-radius:8px;font-size:.9rem;border:1px solid #3b424c;box-shadow:0 2px 8px rgba(0,0,0,.25);transition:transform .15s,background .15s}
  .star:hover{background:#2f363d;transform:translateY(-1px)}
  .star svg{fill:#facc15}
  .hint{color:#9aa4bf;font-size:.82rem;margin:.6rem 0 1.4rem}
  .hint a{color:#9cc2ff}
  .thanks{color:#9aa4bf;font-size:.82rem;margin:1.2rem 0 0}
  .thanks a{color:#9cc2ff}
  small{color:#6b7493}
</style>
</head>
<body>
  <div class="card">
    <span class="tag">pull-only</span>
    <h1>Docker Hub Mirror</h1>
    <p class="sub">基于 Cloudflare Worker 的 Docker Hub 拉取反向代理。仅支持 <code>docker pull</code>。</p>
    <a class="star" href="https://github.com/AinzRimuru/DockerProxyCF" target="_blank" rel="noopener" aria-label="Star on GitHub">
      <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path d="M8 .25a8 8 0 0 0-2.53 15.59c.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8 8 0 0 0 8 .25z"/></svg>
      Star on GitHub
    </a>
    <p class="hint">如果对你有帮助，欢迎到 <a href="https://github.com/AinzRimuru/DockerProxyCF" target="_blank" rel="noopener">AinzRimuru/DockerProxyCF</a> 点个 ⭐ Star 支持一下～</p>
    <pre><code>${examples}</code></pre>
    <p class="sub">也可作为 registry mirror 写入 daemon.json：</p>
    <pre><code>{
  "registry-mirrors": ["https://${host}"]
}</code></pre>
    <p><small>健康检查：<code>GET /v2/</code> &nbsp;|&nbsp; token：<code>/token</code> &nbsp;|&nbsp; 上游：registry-1.docker.io</small></p>
    <p class="thanks">特别鸣谢 <a href="https://linux.do" target="_blank" rel="noopener">LINUX DO</a> 社区</p>
  </div>
</body>
</html>`;
}
