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
<link rel="icon" href="data:image/png;base64,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">
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
