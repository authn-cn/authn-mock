/**
 * Mock 微信开放平台"网站应用"扫码登录。
 *
 * 目标:除了域名(host)不同,其余与微信官方完全一致——同名的 JS SDK(全局 `WxLogin`)、
 * 相同的构造参数、相同的授权回跳(redirect_uri?code=&state=)、相同的后端接口路径
 * (/sns/oauth2/access_token、/sns/userinfo …)与相同的响应字段。扫码部分也跳转到本
 * mock,确认后返回一个**固定测试用户**。
 *
 * 端点:
 *   GET  /wechat/wxLogin.js               —— Mock JS SDK(对应 res.wx.qq.com/.../wxLogin.js),定义全局 WxLogin
 *   GET  /connect/qrconnect               —— 内嵌二维码页(对应 open.weixin.qq.com/connect/qrconnect),iframe 内展示
 *   GET  /connect/poll                    —— 扫码页轮询扫码状态(mock 专用)
 *   GET  /wechat/scan                      —— "手机端"授权页:展示固定用户并确认登录(二维码指向此处)
 *   GET  /sns/oauth2/access_token          —— code 换 access_token(对应 api.weixin.qq.com/sns/oauth2/access_token)
 *   GET  /sns/oauth2/refresh_token         —— 刷新 access_token
 *   GET  /sns/userinfo                     —— 拉取用户信息(固定用户)
 *   GET  /sns/auth                         —— 校验 access_token 是否有效
 *   GET  /wechat/  |  /wechat              —— 控制台 + 内嵌二维码自演示
 *   GET  /wechat/callback                  —— 自演示的回调页(用 code 跑通 token + userinfo)
 *
 * ⚠️ 仅供测试:任何 appid/secret 都被接受,不校验;私钥公开,任何人都能伪造令牌。
 */

import { signJwt, verifyJwt } from './jwt'

const CODE_TTL = 300 // 授权码有效期(秒)
const ACCESS_TTL = 7200 // 微信 access_token 默认 7200s
const REFRESH_TTL = 86400 * 30 // 微信 refresh_token 默认 30 天

const CORS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
}

/** 固定测试用户,字段与微信 /sns/userinfo 返回一致。 */
export const WECHAT_USER = {
  openid: 'mock-openid-oWx0000000000000000000',
  nickname: '微信测试用户',
  sex: 1, // 1 男 2 女 0 未知
  province: 'Guangdong',
  city: 'Shenzhen',
  country: 'CN',
  headimgurl: 'https://mock.authn.example/wechat/avatar/0.png',
  privilege: [] as string[],
  unionid: 'mock-unionid-oUn000000000000000000',
}

function now(): number {
  return Math.floor(Date.now() / 1000)
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...CORS,
      ...headers,
    },
  })
}

/** 微信风格错误:{ errcode, errmsg }。 */
function wxError(errcode: number, errmsg: string): Response {
  return json({ errcode, errmsg })
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

const PAGE_STYLE = `
  body { font-family: -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
         margin: 0; padding: 0; color: #2c3e50; background: #fff; }
  .box { max-width: 300px; margin: 0 auto; padding: 16px 12px; text-align: center; }
  .title { color: #999; font-size: 14px; margin: 4px 0 12px; }
  #qr { display: inline-block; width: 200px; height: 200px; }
  #qr img, #qr canvas { width: 200px !important; height: 200px !important; }
  .st { color: #07c160; font-size: 13px; margin-top: 10px; min-height: 18px; }
  .hint { color: #b2b2b2; font-size: 12px; margin-top: 8px; line-height: 1.6; }
  .dev { display: inline-block; margin-top: 10px; font-size: 12px; color: #576b95; text-decoration: none; }
`

// ---------------------------------------------------------------------------
// 扫码会话(ticket)。扫码轮询天生需要跨请求/跨 isolate 的共享状态,故落库 D1
// (与 mail.ts 同款 Store 模式:d1TicketStore 用于生产,memTicketStore 用于测试/回退)。
// ---------------------------------------------------------------------------

const TICKET_TTL_MS = CODE_TTL * 1000

export type TicketStatus = 'PENDING' | 'CONFIRMED' | 'CANCELLED'

export interface Ticket {
  id: string
  status: TicketStatus
  code: string | null
  appid: string
  scope: string
  created_at: number // Unix 毫秒
}

export interface TicketStore {
  create(t: Ticket): Promise<void>
  get(id: string): Promise<Ticket | null>
  update(id: string, patch: { status?: TicketStatus; code?: string }): Promise<void>
}

/** D1 实现。 */
export function d1TicketStore(db: D1Database): TicketStore {
  return {
    async create(t) {
      await db
        .prepare(
          `INSERT INTO wechat_tickets (id, status, code, appid, scope, created_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .bind(t.id, t.status, t.code, t.appid, t.scope, t.created_at)
        .run()
      // 顺手清理过期会话(mock 自净)。
      await db.prepare(`DELETE FROM wechat_tickets WHERE created_at < ?`).bind(t.created_at - TICKET_TTL_MS).run()
    },
    async get(id) {
      return (await db.prepare(`SELECT * FROM wechat_tickets WHERE id = ?`).bind(id).first<Ticket>()) ?? null
    },
    async update(id, patch) {
      const sets: string[] = []
      const vals: unknown[] = []
      if (patch.status !== undefined) { sets.push('status = ?'); vals.push(patch.status) }
      if (patch.code !== undefined) { sets.push('code = ?'); vals.push(patch.code) }
      if (!sets.length) return
      vals.push(id)
      await db.prepare(`UPDATE wechat_tickets SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run()
    },
  }
}

/** 内存实现(测试 / 无 D1 绑定时回退)。 */
const memTickets = new Map<string, Ticket>()
export function memTicketStore(): TicketStore {
  return {
    async create(t) {
      const cutoff = t.created_at - TICKET_TTL_MS
      for (const [k, v] of memTickets) if (v.created_at < cutoff) memTickets.delete(k)
      memTickets.set(t.id, { ...t })
    },
    async get(id) {
      return memTickets.get(id) ?? null
    },
    async update(id, patch) {
      const t = memTickets.get(id)
      if (t) Object.assign(t, patch)
    },
  }
}

function ticketExpired(t: Ticket): boolean {
  return Date.now() - t.created_at > TICKET_TTL_MS
}

async function newTicket(store: TicketStore, appid: string, scope: string): Promise<string> {
  const id = crypto.randomUUID().replace(/-/g, '')
  await store.create({ id, status: 'PENDING', code: null, appid, scope, created_at: Date.now() })
  return id
}

// ---------------------------------------------------------------------------
// JS SDK —— 对应 https://res.wx.qq.com/connect/zh_CN/htmledition/js/wxLogin.js
// 用法与官方完全一致:new WxLogin({ id, appid, scope, redirect_uri, state, style, href, self_redirect })
// ---------------------------------------------------------------------------

export function wxLoginJs(origin: string): Response {
  const connect = `${origin}/connect/qrconnect`
  // 注意:此处用字符串拼接而非模板串,避免与浏览器运行时代码混淆。
  const js = `;(function (global) {
  function WxLogin(opts) {
    opts = opts || {};
    // 与官方 wxLogin.js 完全一致:参数按原样拼接,不做 encodeURIComponent
    // (官方约定由调用方对 redirect_uri 做 urlencode)。
    var params = {
      appid: opts.appid || "",
      scope: opts.scope || "snsapi_login",
      redirect_uri: opts.redirect_uri || "",
      state: opts.state || "",
      login_type: "jssdk",
      self_redirect: opts.self_redirect === true,
      styletype: opts.styletype || "",
      sizetype: opts.sizetype || "",
      bgcolor: opts.bgcolor || "",
      rst: opts.rst || "",
      style: opts.style || "",
      href: opts.href || ""
    };
    var qs = [];
    for (var k in params) { qs.push(k + "=" + params[k]); }
    var src = ${JSON.stringify(connect)} + "?" + qs.join("&");
    var el = document.getElementById(opts.id);
    if (!el) { return this; }
    var iframe = document.createElement("iframe");
    iframe.src = src;
    iframe.frameBorder = "0";
    iframe.allowTransparency = "true";
    iframe.scrolling = "no";
    iframe.width = "300px";
    iframe.height = "400px";
    // Chrome 142+ 本地网络访问权限提示的兼容(与官方 wxLogin.js 一致)。
    iframe.setAttribute("allow", "local-network-access");
    el.innerHTML = "";
    el.appendChild(iframe);
    return this;
  }
  global.WxLogin = WxLogin;
})(typeof window !== "undefined" ? window : this);
`
  return new Response(js, {
    headers: {
      'Content-Type': 'application/javascript; charset=utf-8',
      'Cache-Control': 'no-store',
      ...CORS,
    },
  })
}

// ---------------------------------------------------------------------------
// 内嵌二维码页 —— 对应 https://open.weixin.qq.com/connect/qrconnect
// ---------------------------------------------------------------------------

export async function qrconnect(req: Request, origin: string, store: TicketStore): Promise<Response> {
  const q = new URL(req.url).searchParams
  const appid = q.get('appid') ?? ''
  const scope = q.get('scope') ?? 'snsapi_login'
  // URLSearchParams 已解码一次(等同真实 qrconnect 服务端收到 urlencode 后的 redirect_uri)。
  const redirectUri = q.get('redirect_uri') ?? ''
  const state = q.get('state') ?? ''
  const selfRedirect = q.get('self_redirect') === 'true'

  if (!redirectUri || !/^https?:\/\//.test(redirectUri)) {
    return new Response('该链接无法访问：redirect_uri 缺失或不是绝对 http(s) 地址', {
      status: 400,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    })
  }

  const ticket = await newTicket(store, appid, scope)
  const scanUrl = `${origin}/wechat/scan?ticket=${ticket}`

  const html = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>微信登录（Mock）</title><style>${PAGE_STYLE}</style></head>
<body>
<div class="box">
  <div class="title">请使用微信扫一扫登录<br>“Mock 网站应用”</div>
  <div id="qr"></div>
  <div class="st" id="st">等待扫码…</div>
  <div class="hint">这是 Mock 微信,没有真实微信客户端。<br>手机扫码或点下方链接即可模拟。</div>
  <a class="dev" id="scanlink" href="${esc(scanUrl)}" target="_blank" rel="noopener">（开发者）点此模拟扫码 →</a>
</div>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
<script>
(function () {
  var TICKET = ${JSON.stringify(ticket)};
  var SCAN = ${JSON.stringify(scanUrl)};
  var REDIRECT = ${JSON.stringify(redirectUri)};
  var STATE = ${JSON.stringify(state)};
  var SELF = ${selfRedirect ? 'true' : 'false'};
  var POLL = ${JSON.stringify(origin + '/connect/poll')};

  try {
    if (typeof QRCode !== "undefined") {
      new QRCode(document.getElementById("qr"), { text: SCAN, width: 200, height: 200, correctLevel: QRCode.CorrectLevel.M });
    } else { throw new Error("no qr lib"); }
  } catch (e) {
    document.getElementById("qr").innerHTML = '<a href="' + SCAN + '" target="_blank" rel="noopener" style="font-size:13px;color:#576b95">二维码库未加载，点此模拟扫码</a>';
  }

  function finish(code) {
    var sep = REDIRECT.indexOf("?") >= 0 ? "&" : "?";
    var url = REDIRECT + sep + "code=" + encodeURIComponent(code);
    if (STATE) { url += "&state=" + encodeURIComponent(STATE); }
    if (SELF) { location.href = url; }
    else { try { window.top.location.href = url; } catch (e) { location.href = url; } }
  }

  var timer = setInterval(function () {
    fetch(POLL + "?ticket=" + encodeURIComponent(TICKET))
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.status === "CONFIRMED" && d.code) {
          clearInterval(timer);
          document.getElementById("st").textContent = "扫码成功，正在跳转…";
          finish(d.code);
        } else if (d.status === "SCANNED") {
          document.getElementById("st").textContent = "已扫码，请在手机上确认";
        } else if (d.status === "CANCELLED") {
          clearInterval(timer);
          document.getElementById("st").textContent = "已取消登录";
        } else if (d.status === "EXPIRED") {
          clearInterval(timer);
          document.getElementById("st").textContent = "二维码已过期，请刷新页面";
        }
      })
      .catch(function () {});
  }, 1500);
})();
</script>
</body></html>`

  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  })
}

// ---------------------------------------------------------------------------
// 轮询扫码状态(mock 专用,供 qrconnect 页调用)
// ---------------------------------------------------------------------------

export async function poll(req: Request, store: TicketStore): Promise<Response> {
  const ticketId = new URL(req.url).searchParams.get('ticket') ?? ''
  const t = await store.get(ticketId)
  if (!t || ticketExpired(t)) return json({ status: 'EXPIRED' })
  if (t.status === 'CANCELLED') return json({ status: 'CANCELLED' })
  if (t.status === 'CONFIRMED' && t.code) return json({ status: 'CONFIRMED', code: t.code })
  return json({ status: 'PENDING' })
}

// ---------------------------------------------------------------------------
// "手机端"授权页:展示固定用户并确认/取消登录(二维码指向此处)
// ---------------------------------------------------------------------------

export async function scan(req: Request, store: TicketStore): Promise<Response> {
  const q = new URL(req.url).searchParams
  const ticketId = q.get('ticket') ?? ''
  const action = q.get('action')
  const t = await store.get(ticketId)

  if (!t || ticketExpired(t)) {
    return scanPage('二维码已过期', '请回到电脑刷新页面后重新扫码。', ticketId, false)
  }

  if (action === 'cancel') {
    await store.update(ticketId, { status: 'CANCELLED' })
    return scanPage('已取消', '你已取消本次登录。', ticketId, false)
  }

  if (action === 'confirm') {
    // 授权码 = 短时效签名 JWT(与 OIDC mock 一致的无状态签名风格)。
    const code = await signJwt({
      token_use: 'wechat_code',
      openid: WECHAT_USER.openid,
      appid: t.appid,
      scope: t.scope,
      exp: now() + CODE_TTL,
    })
    await store.update(ticketId, { status: 'CONFIRMED', code })
    return scanPage('登录成功', '已确认登录，请回到电脑端。', ticketId, false)
  }

  // 展示固定用户 + 确认/取消按钮
  return scanPage(
    '确认登录',
    `即将以下面的微信账号登录 “Mock 网站应用”：`,
    ticketId,
    true,
  )
}

function scanPage(title: string, subtitle: string, ticketId: string, showButtons: boolean): Response {
  const u = WECHAT_USER
  const userCard = `
    <div style="margin:16px 0;display:flex;align-items:center;justify-content:center;gap:10px">
      <div style="width:44px;height:44px;border-radius:50%;background:#07c160;color:#fff;display:flex;align-items:center;justify-content:center;font-size:18px">微</div>
      <div style="text-align:left">
        <div style="font-weight:600">${esc(u.nickname)}</div>
        <div style="color:#999;font-size:12px">openid: ${esc(u.openid)}</div>
      </div>
    </div>`
  const buttons = showButtons
    ? `<a href="/wechat/scan?ticket=${esc(ticketId)}&action=confirm"
          style="display:block;margin:8px 0;padding:11px;background:#07c160;color:#fff;border-radius:6px;text-decoration:none;font-size:15px">确认登录</a>
       <a href="/wechat/scan?ticket=${esc(ticketId)}&action=cancel"
          style="display:block;margin:8px 0;padding:11px;background:#f2f2f2;color:#576b95;border-radius:6px;text-decoration:none;font-size:15px">取消</a>`
    : `<a href="/wechat/" style="display:inline-block;margin-top:12px;color:#576b95;font-size:13px;text-decoration:none">返回</a>`

  const html = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} — 微信登录（Mock）</title></head>
<body style="font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;background:#ededed;margin:0">
<div style="max-width:360px;margin:0 auto;padding:40px 20px;text-align:center">
  <div style="background:#fff;border-radius:12px;padding:24px 20px">
    <div style="font-size:18px;font-weight:600">${esc(title)}</div>
    <div style="color:#666;font-size:13px;margin-top:6px">${esc(subtitle)}</div>
    ${showButtons ? userCard : ''}
    ${buttons}
  </div>
  <div style="color:#b2b2b2;font-size:12px;margin-top:16px">Mock 微信 · 仅供测试</div>
</div>
</body></html>`
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  })
}

// ---------------------------------------------------------------------------
// 后端 API —— 镜像 api.weixin.qq.com/sns/*(字段与官方一致)
// ---------------------------------------------------------------------------

/** GET /sns/oauth2/access_token?appid=&secret=&code=&grant_type=authorization_code */
export async function snsAccessToken(req: Request): Promise<Response> {
  const q = new URL(req.url).searchParams
  const code = q.get('code') ?? ''
  const grantType = q.get('grant_type')
  if (grantType !== 'authorization_code') return wxError(40002, 'invalid grant_type')
  if (!code) return wxError(41008, 'missing code')

  const payload = await verifyJwt(code)
  if (!payload || payload.token_use !== 'wechat_code') return wxError(40029, 'invalid code')

  const openid = String(payload.openid)
  const scope = String(payload.scope ?? 'snsapi_login')
  return json(await issueTokens(openid, scope))
}

/** GET /sns/oauth2/refresh_token?appid=&grant_type=refresh_token&refresh_token= */
export async function snsRefreshToken(req: Request): Promise<Response> {
  const q = new URL(req.url).searchParams
  const grantType = q.get('grant_type')
  const rt = q.get('refresh_token') ?? ''
  if (grantType !== 'refresh_token') return wxError(40002, 'invalid grant_type')
  const payload = await verifyJwt(rt)
  if (!payload || payload.token_use !== 'wechat_refresh') return wxError(40030, 'invalid refresh_token')
  return json(await issueTokens(String(payload.openid), String(payload.scope ?? 'snsapi_login')))
}

async function issueTokens(openid: string, scope: string): Promise<Record<string, unknown>> {
  const accessToken = await signJwt({
    token_use: 'wechat_access',
    openid,
    scope,
    exp: now() + ACCESS_TTL,
  })
  const refreshToken = await signJwt({
    token_use: 'wechat_refresh',
    openid,
    scope,
    exp: now() + REFRESH_TTL,
  })
  return {
    access_token: accessToken,
    expires_in: ACCESS_TTL,
    refresh_token: refreshToken,
    openid,
    scope,
    unionid: WECHAT_USER.unionid,
  }
}

/** GET /sns/userinfo?access_token=&openid=&lang=zh_CN */
export async function snsUserinfo(req: Request): Promise<Response> {
  const q = new URL(req.url).searchParams
  const accessToken = q.get('access_token') ?? ''
  const payload = await verifyJwt(accessToken)
  if (!payload || payload.token_use !== 'wechat_access') return wxError(40001, 'invalid access_token')
  return json({ ...WECHAT_USER })
}

/** GET /sns/auth?access_token=&openid= */
export async function snsAuth(req: Request): Promise<Response> {
  const accessToken = new URL(req.url).searchParams.get('access_token') ?? ''
  const payload = await verifyJwt(accessToken)
  if (!payload || payload.token_use !== 'wechat_access') return wxError(40001, 'invalid access_token')
  return json({ errcode: 0, errmsg: 'ok' })
}

// ---------------------------------------------------------------------------
// 控制台 + 自演示(内嵌二维码 → 回调 → token → userinfo)
// ---------------------------------------------------------------------------

export function wechatHome(origin: string): Response {
  const html = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mock 微信扫码登录</title>
<style>
  body { font-family:-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif; max-width:760px; margin:2.5rem auto; padding:0 1.2rem; line-height:1.7; color:#2c3e50; }
  h1{font-size:1.5rem} h2{font-size:1.1rem;margin-top:1.8rem}
  code,pre{font-family:ui-monospace,monospace;background:#f6f8fa;border-radius:4px}
  code{padding:.12rem .38rem;font-size:.88em} pre{padding:.9rem;overflow-x:auto;font-size:.82rem}
  table{border-collapse:collapse;width:100%;font-size:.9rem} th,td{border:1px solid #dfe2e5;padding:.4rem .7rem;text-align:left}
  a{color:#07c160} .warn{background:#fff3cd;border-left:4px solid #e0a800;padding:.7rem 1rem;border-radius:4px}
  .demo{display:flex;gap:2rem;flex-wrap:wrap;align-items:flex-start} #wx_login{min-width:300px}
</style></head>
<body>
<h1>🟢 Mock 微信扫码登录</h1>
<p class="warn"><strong>仅供开发与测试。</strong>不校验 appid/secret,固定返回一个测试用户;签名私钥公开,任何人都能伪造令牌。生产系统绝不能信任此服务。</p>
<p>与微信开放平台"网站应用"扫码登录 <strong>输入输出完全一致,只是域名不同</strong>:同名 <code>WxLogin</code> SDK、相同回跳 <code>redirect_uri?code=&amp;state=</code>、相同的 <code>/sns/*</code> 接口与字段。</p>

<h2>在线自演示</h2>
<div class="demo">
  <div id="wx_login"></div>
  <div style="flex:1;min-width:260px">
    <p>右/上方是用本站 <code>WxLogin</code> SDK 内嵌的二维码。手机扫码或点二维码下方"模拟扫码"→"确认登录",页面会带 <code>code</code> 回跳到 <code>/wechat/callback</code>,并自动换取 token 与用户信息。</p>
  </div>
</div>
<script src="${origin}/wechat/wxLogin.js"></script>
<script>
  new WxLogin({
    id: "wx_login",
    appid: "wxmockappid0000000",
    scope: "snsapi_login",
    redirect_uri: encodeURIComponent("${origin}/wechat/callback"),
    state: "demo-state-123"
  });
</script>

<h2>接入方式(与官方一致)</h2>
<pre>&lt;div id="login_container"&gt;&lt;/div&gt;
&lt;script src="${origin}/wechat/wxLogin.js"&gt;&lt;/script&gt;
&lt;script&gt;
  new WxLogin({
    id: "login_container",
    appid: "你的_appid",
    scope: "snsapi_login",
    redirect_uri: encodeURIComponent("https://your-app.example/callback"),  // 官方约定:调用方 urlencode;回调会带 ?code=&state=
    state: "任意防伪串",
    style: "black",            // 可选
    self_redirect: false       // false=顶层窗口跳转,true=iframe 内跳转
  });
&lt;/script&gt;</pre>

<h2>后端接口</h2>
<table>
<tr><th>JS SDK</th><td><a href="${origin}/wechat/wxLogin.js"><code>${origin}/wechat/wxLogin.js</code></a></td></tr>
<tr><th>扫码页</th><td><code>${origin}/connect/qrconnect</code></td></tr>
<tr><th>code 换 token</th><td><code>${origin}/sns/oauth2/access_token?appid=&amp;secret=&amp;code=&amp;grant_type=authorization_code</code></td></tr>
<tr><th>刷新 token</th><td><code>${origin}/sns/oauth2/refresh_token?appid=&amp;grant_type=refresh_token&amp;refresh_token=</code></td></tr>
<tr><th>用户信息</th><td><code>${origin}/sns/userinfo?access_token=&amp;openid=</code></td></tr>
<tr><th>校验 token</th><td><code>${origin}/sns/auth?access_token=&amp;openid=</code></td></tr>
</table>
<p>后端拿到 <code>code</code> 后:</p>
<pre>curl "${origin}/sns/oauth2/access_token?appid=demo&amp;secret=x&amp;code=&lt;CODE&gt;&amp;grant_type=authorization_code"
# → { access_token, expires_in, refresh_token, openid, scope, unionid }
curl "${origin}/sns/userinfo?access_token=&lt;AT&gt;&amp;openid=&lt;OPENID&gt;"
# → { openid, nickname, sex, province, city, country, headimgurl, privilege, unionid }</pre>

<h2>固定测试用户</h2>
<table>
<tr><th>openid</th><td><code>${WECHAT_USER.openid}</code></td></tr>
<tr><th>unionid</th><td><code>${WECHAT_USER.unionid}</code></td></tr>
<tr><th>nickname</th><td>${esc(WECHAT_USER.nickname)}</td></tr>
</table>
<p><a href="https://authn-cn.pages.dev/">← 返回 authn-cn 文档站</a></p>
</body></html>`
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  })
}

/** 自演示回调:展示 code,并用客户端 fetch 跑通 token + userinfo(CORS 全开)。 */
export function wechatCallback(req: Request, origin: string): Response {
  const q = new URL(req.url).searchParams
  const code = q.get('code') ?? ''
  const state = q.get('state') ?? ''
  const html = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>回调 — Mock 微信扫码登录</title>
<style>
  body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;max-width:760px;margin:2.5rem auto;padding:0 1.2rem;line-height:1.7;color:#2c3e50}
  h1{font-size:1.4rem} pre{background:#f6f8fa;border-radius:6px;padding:.9rem;overflow-x:auto;font-size:.82rem;white-space:pre-wrap;word-break:break-all}
  .k{color:#07c160;font-weight:600} a{color:#07c160}
</style></head>
<body>
<h1>✅ 扫码登录回调</h1>
<p><span class="k">code</span> = <code>${esc(code) || '(无)'}</code></p>
<p><span class="k">state</span> = <code>${esc(state) || '(无)'}</code></p>
<h3>用 code 换 access_token → userinfo</h3>
<pre id="out">处理中…</pre>
<p><a href="/wechat/">← 再试一次</a></p>
<script>
(function () {
  var code = ${JSON.stringify(code)};
  var origin = ${JSON.stringify(origin)};
  var out = document.getElementById("out");
  if (!code) { out.textContent = "没有拿到 code。"; return; }
  fetch(origin + "/sns/oauth2/access_token?appid=demo&secret=x&code=" + encodeURIComponent(code) + "&grant_type=authorization_code")
    .then(function (r) { return r.json(); })
    .then(function (tok) {
      if (tok.errcode) { throw new Error("token: " + JSON.stringify(tok)); }
      out.textContent = "access_token 响应:\\n" + JSON.stringify(tok, null, 2) + "\\n\\n拉取用户信息…";
      return fetch(origin + "/sns/userinfo?access_token=" + encodeURIComponent(tok.access_token) + "&openid=" + encodeURIComponent(tok.openid))
        .then(function (r) { return r.json(); })
        .then(function (ui) {
          out.textContent = "access_token 响应:\\n" + JSON.stringify(tok, null, 2) + "\\n\\nuserinfo 响应:\\n" + JSON.stringify(ui, null, 2);
        });
    })
    .catch(function (e) { out.textContent = "出错: " + e.message; });
})();
</script>
</body></html>`
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  })
}
