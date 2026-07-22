/**
 * Mock 企业微信(WeCom)扫码登录 —— 网页扫码登录 / 构造扫码登录链接。
 *
 * 所有端点统一收敛在 `/wecom` 命名空间下(把官方 base URL 换成 `<本站>/wecom` 即可):
 *
 *   GET  /wecom/wwLogin.js                 —— Mock JS SDK,定义全局 WwLogin(对应 wwcdn.weixin.qq.com/.../wwLogin-*.js)
 *   GET  /wecom/sso/qrConnect              —— 内嵌二维码页(对应 open.work.weixin.qq.com/wwopen/sso/qrConnect)
 *   GET  /wecom/sso/poll                   —— 扫码状态轮询(mock 专用)
 *   GET  /wecom/scan                        —— "手机端"授权页:展示固定成员并确认登录(二维码指向此处)
 *   GET  /wecom/cgi-bin/gettoken            —— corpid+corpsecret 换"应用级" access_token
 *   GET  /wecom/cgi-bin/auth/getuserinfo    —— access_token+code 换 userid(+ user_ticket)
 *   GET  /wecom/cgi-bin/user/get            —— access_token+userid 读通讯录成员详情
 *   POST /wecom/cgi-bin/auth/getuserdetail  —— user_ticket 读敏感信息(可选)
 *   GET  /wecom/  |  /wecom                 —— 控制台 + 内嵌二维码自演示
 *   GET  /wecom/callback                    —— 自演示回调页
 *
 * 企业微信取用户信息与微信"网站应用"不同,分三步:gettoken → auth/getuserinfo → user/get。
 * 扫码环节也跳转到本 mock,确认后返回一个**固定测试成员**。
 * 扫码会话(ticket)复用 wechat.ts 的 D1 TicketStore(同一张 wechat_tickets 表)。
 *
 * ⚠️ 仅供测试:任何 corpid/corpsecret/agentid 都被接受,不校验;私钥公开,任何人都能伪造令牌。
 */

import { signJwt, verifyJwt } from './jwt'
import type { TicketStore } from './wechat'

const CODE_TTL = 300
const ACCESS_TTL = 7200 // 企业微信 access_token 默认 7200s
const TICKET_TTL_MS = CODE_TTL * 1000

const CORS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
}

/** 固定测试成员,字段与企业微信 /cgi-bin/user/get 返回一致。 */
export const WECOM_MEMBER = {
  userid: 'zhangsan',
  name: '张三',
  department: [1],
  order: [1],
  position: '产品经理',
  mobile: '13800000000',
  gender: '1', // 1 男 2 女 0 未定义
  email: 'zhangsan@mock.authn.example',
  biz_mail: 'zhangsan@mock.work',
  avatar: 'https://mock.authn.example/wecom/avatar/0.png',
  thumb_avatar: 'https://mock.authn.example/wecom/avatar/0_100.png',
  telephone: '',
  alias: 'zs',
  status: 1,
  isleader: 0,
  extattr: { attrs: [] as unknown[] },
  qr_code: 'https://open.work.weixin.qq.com/wwopen/userQRCode?vcode=mock',
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

/** 企业微信风格错误:{ errcode, errmsg }。 */
function wwError(errcode: number, errmsg: string): Response {
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
  .st { color: #0082ef; font-size: 13px; margin-top: 10px; min-height: 18px; }
  .hint { color: #b2b2b2; font-size: 12px; margin-top: 8px; line-height: 1.6; }
  .dev { display: inline-block; margin-top: 10px; font-size: 12px; color: #0082ef; text-decoration: none; }
`

async function newTicket(store: TicketStore, corpid: string, agentid: string): Promise<string> {
  const id = crypto.randomUUID().replace(/-/g, '')
  // 复用 wechat_tickets 表:appid 列存 corpid,scope 列存 agentid。
  await store.create({ id, status: 'PENDING', code: null, appid: corpid, scope: agentid, created_at: Date.now() })
  return id
}

function ticketExpired(createdAt: number): boolean {
  return Date.now() - createdAt > TICKET_TTL_MS
}

// ---------------------------------------------------------------------------
// JS SDK —— 对应 wwcdn.weixin.qq.com/node/wework/wwopen/js/wwLogin-1.x.x.js
// 用法与官方一致:new WwLogin({ id, appid, agentid, redirect_uri, state, href, lang })
// (appid 即 corpid;新版 @wecom/jssdk 的 createWWLoginPanel 指向同一套 qrConnect 与后端接口)
// ---------------------------------------------------------------------------

export function wwLoginJs(origin: string): Response {
  const connect = `${origin}/wecom/sso/qrConnect`
  const js = `;(function (global) {
  function WwLogin(opts) {
    opts = opts || {};
    // 与官方 wwLogin.js 完全一致:参数按原样拼接,不做 encodeURIComponent
    // (官方约定由调用方对 redirect_uri 做 urlencode)。
    var params = {
      appid: opts.appid || "",
      agentid: opts.agentid || "",
      redirect_uri: opts.redirect_uri || "",
      state: opts.state || "",
      login_type: opts.login_type || "CorpApp",
      redirect_type: opts.redirect_type || "",
      lang: opts.lang || "zh",
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
    iframe.setAttribute("allow", "local-network-access");
    el.innerHTML = "";
    el.appendChild(iframe);
    return this;
  }
  global.WwLogin = WwLogin;
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
// 内嵌二维码页 —— 对应 open.work.weixin.qq.com/wwopen/sso/qrConnect
// ---------------------------------------------------------------------------

export async function qrConnect(req: Request, origin: string, store: TicketStore): Promise<Response> {
  const q = new URL(req.url).searchParams
  const corpid = q.get('appid') ?? ''
  const agentid = q.get('agentid') ?? ''
  // URLSearchParams 已解码一次(等同真实 qrConnect 服务端收到 urlencode 后的 redirect_uri)。
  const redirectUri = q.get('redirect_uri') ?? ''
  const state = q.get('state') ?? ''
  const redirectType = q.get('redirect_type') // 'callback' 在 iframe 内跳转;否则顶层窗口跳转

  if (!redirectUri || !/^https?:\/\//.test(redirectUri)) {
    return new Response('该链接无法访问：redirect_uri 缺失或不是绝对 http(s) 地址', {
      status: 400,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    })
  }

  const ticket = await newTicket(store, corpid, agentid)
  const scanUrl = `${origin}/wecom/scan?ticket=${ticket}`
  const selfRedirect = redirectType === 'callback'

  const html = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>企业微信登录（Mock）</title><style>${PAGE_STYLE}</style></head>
<body>
<div class="box">
  <div class="title">请使用企业微信扫一扫登录<br>“Mock 企业应用”</div>
  <div id="qr"></div>
  <div class="st" id="st">等待扫码…</div>
  <div class="hint">这是 Mock 企业微信,没有真实客户端。<br>手机扫码或点下方链接即可模拟。</div>
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
  var POLL = ${JSON.stringify(origin + '/wecom/sso/poll')};

  try {
    if (typeof QRCode !== "undefined") {
      new QRCode(document.getElementById("qr"), { text: SCAN, width: 200, height: 200, correctLevel: QRCode.CorrectLevel.M });
    } else { throw new Error("no qr lib"); }
  } catch (e) {
    document.getElementById("qr").innerHTML = '<a href="' + SCAN + '" target="_blank" rel="noopener" style="font-size:13px;color:#0082ef">二维码库未加载，点此模拟扫码</a>';
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
// "手机端"授权页:展示固定成员并确认/取消登录(二维码指向此处)
// ---------------------------------------------------------------------------

export async function scan(req: Request, store: TicketStore): Promise<Response> {
  const q = new URL(req.url).searchParams
  const ticketId = q.get('ticket') ?? ''
  const action = q.get('action')
  const t = await store.get(ticketId)

  if (!t || ticketExpired(t.created_at)) {
    return scanPage('二维码已过期', '请回到电脑刷新页面后重新扫码。', ticketId, false)
  }

  if (action === 'cancel') {
    await store.update(ticketId, { status: 'CANCELLED' })
    return scanPage('已取消', '你已取消本次登录。', ticketId, false)
  }

  if (action === 'confirm') {
    // 授权码 = 短时效签名 JWT;t.appid=corpid,t.scope=agentid。
    const code = await signJwt({
      token_use: 'wecom_code',
      userid: WECOM_MEMBER.userid,
      corpid: t.appid,
      agentid: t.scope,
      exp: now() + CODE_TTL,
    })
    await store.update(ticketId, { status: 'CONFIRMED', code })
    return scanPage('登录成功', '已确认登录，请回到电脑端。', ticketId, false)
  }

  return scanPage('确认登录', '即将以下面的企业微信成员登录 “Mock 企业应用”：', ticketId, true)
}

function scanPage(title: string, subtitle: string, ticketId: string, showButtons: boolean): Response {
  const m = WECOM_MEMBER
  const userCard = `
    <div style="margin:16px 0;display:flex;align-items:center;justify-content:center;gap:10px">
      <div style="width:44px;height:44px;border-radius:6px;background:#0082ef;color:#fff;display:flex;align-items:center;justify-content:center;font-size:16px">${esc(m.name.slice(-2))}</div>
      <div style="text-align:left">
        <div style="font-weight:600">${esc(m.name)} · ${esc(m.position)}</div>
        <div style="color:#999;font-size:12px">userid: ${esc(m.userid)}</div>
      </div>
    </div>`
  const buttons = showButtons
    ? `<a href="/wecom/scan?ticket=${esc(ticketId)}&action=confirm"
          style="display:block;margin:8px 0;padding:11px;background:#0082ef;color:#fff;border-radius:6px;text-decoration:none;font-size:15px">确认登录</a>
       <a href="/wecom/scan?ticket=${esc(ticketId)}&action=cancel"
          style="display:block;margin:8px 0;padding:11px;background:#f2f2f2;color:#576b95;border-radius:6px;text-decoration:none;font-size:15px">取消</a>`
    : `<a href="/wecom/" style="display:inline-block;margin-top:12px;color:#0082ef;font-size:13px;text-decoration:none">返回</a>`

  const html = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} — 企业微信登录（Mock）</title></head>
<body style="font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;background:#ededed;margin:0">
<div style="max-width:360px;margin:0 auto;padding:40px 20px;text-align:center">
  <div style="background:#fff;border-radius:12px;padding:24px 20px">
    <div style="font-size:18px;font-weight:600">${esc(title)}</div>
    <div style="color:#666;font-size:13px;margin-top:6px">${esc(subtitle)}</div>
    ${showButtons ? userCard : ''}
    ${buttons}
  </div>
  <div style="color:#b2b2b2;font-size:12px;margin-top:16px">Mock 企业微信 · 仅供测试</div>
</div>
</body></html>`
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  })
}

// ---------------------------------------------------------------------------
// 后端 API —— 镜像 qyapi.weixin.qq.com/cgi-bin/*(字段与官方一致)
// ---------------------------------------------------------------------------

/** GET /wecom/cgi-bin/gettoken?corpid=&corpsecret= —— 换"应用级" access_token */
export async function gettoken(req: Request): Promise<Response> {
  const q = new URL(req.url).searchParams
  const corpid = q.get('corpid') ?? ''
  const corpsecret = q.get('corpsecret') ?? ''
  if (!corpid) return wwError(40013, 'invalid corpid')
  if (!corpsecret) return wwError(41004, 'missing corpsecret')
  const accessToken = await signJwt({
    token_use: 'wecom_access',
    corpid,
    exp: now() + ACCESS_TTL,
  })
  return json({ errcode: 0, errmsg: 'ok', access_token: accessToken, expires_in: ACCESS_TTL })
}

/** GET /wecom/cgi-bin/auth/getuserinfo?access_token=&code= —— code 换 userid(+ user_ticket) */
export async function authGetUserInfo(req: Request): Promise<Response> {
  const q = new URL(req.url).searchParams
  const at = await verifyJwt(q.get('access_token') ?? '')
  if (!at || at.token_use !== 'wecom_access') return wwError(40014, 'invalid access_token')

  const codePayload = await verifyJwt(q.get('code') ?? '')
  if (!codePayload || codePayload.token_use !== 'wecom_code') return wwError(40029, 'invalid code')

  const userid = String(codePayload.userid)
  // user_ticket 用于后续拉取敏感信息(有效期通常 1800s)。
  const userTicket = await signJwt({
    token_use: 'wecom_user_ticket',
    userid,
    exp: now() + 1800,
  })
  return json({ errcode: 0, errmsg: 'ok', userid, user_ticket: userTicket })
}

/** GET /wecom/cgi-bin/user/get?access_token=&userid= —— 读取通讯录成员详情 */
export async function userGet(req: Request): Promise<Response> {
  const q = new URL(req.url).searchParams
  const at = await verifyJwt(q.get('access_token') ?? '')
  if (!at || at.token_use !== 'wecom_access') return wwError(40014, 'invalid access_token')
  const userid = q.get('userid') ?? ''
  if (userid !== WECOM_MEMBER.userid) return wwError(60111, `userid not found: ${userid}`)
  return json({ errcode: 0, errmsg: 'ok', ...WECOM_MEMBER })
}

/** POST /wecom/cgi-bin/auth/getuserdetail  body: { user_ticket } —— 用 user_ticket 读敏感信息 */
export async function getUserDetail(req: Request): Promise<Response> {
  const at = await verifyJwt(new URL(req.url).searchParams.get('access_token') ?? '')
  if (!at || at.token_use !== 'wecom_access') return wwError(40014, 'invalid access_token')
  let userTicket = ''
  try {
    const body = (await req.json()) as { user_ticket?: string }
    userTicket = body.user_ticket ?? ''
  } catch {
    return wwError(41017, 'missing user_ticket')
  }
  const tk = await verifyJwt(userTicket)
  if (!tk || tk.token_use !== 'wecom_user_ticket') return wwError(41017, 'invalid user_ticket')
  const m = WECOM_MEMBER
  return json({
    errcode: 0,
    errmsg: 'ok',
    userid: m.userid,
    gender: m.gender,
    avatar: m.avatar,
    qr_code: m.qr_code,
    mobile: m.mobile,
    email: m.email,
    biz_mail: m.biz_mail,
    address: '广东省深圳市',
  })
}

// ---------------------------------------------------------------------------
// 控制台 + 自演示
// ---------------------------------------------------------------------------

export function wecomHome(origin: string): Response {
  const html = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mock 企业微信扫码登录</title>
<style>
  body { font-family:-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif; max-width:760px; margin:2.5rem auto; padding:0 1.2rem; line-height:1.7; color:#2c3e50; }
  h1{font-size:1.5rem} h2{font-size:1.1rem;margin-top:1.8rem}
  code,pre{font-family:ui-monospace,monospace;background:#f6f8fa;border-radius:4px}
  code{padding:.12rem .38rem;font-size:.88em} pre{padding:.9rem;overflow-x:auto;font-size:.82rem}
  table{border-collapse:collapse;width:100%;font-size:.9rem} th,td{border:1px solid #dfe2e5;padding:.4rem .7rem;text-align:left}
  a{color:#0082ef} .warn{background:#fff3cd;border-left:4px solid #e0a800;padding:.7rem 1rem;border-radius:4px}
  .demo{display:flex;gap:2rem;flex-wrap:wrap;align-items:flex-start} #ww_login{min-width:300px}
</style></head>
<body>
<h1>🔵 Mock 企业微信扫码登录</h1>
<p class="warn"><strong>仅供开发与测试。</strong>不校验 corpid/corpsecret/agentid,固定返回一个测试成员;签名私钥公开,任何人都能伪造令牌。生产系统绝不能信任此服务。</p>
<p>与企业微信官方网页扫码登录 <strong>输入输出一致</strong>:同名 <code>WwLogin</code> SDK、相同回跳 <code>redirect_uri?code=&amp;state=</code>、相同的字段。所有端点收敛在 <code>/wecom</code> 下——把官方 base URL 换成 <code>${origin}/wecom</code> 即可。取用户信息按企业微信规范分三步:<code>gettoken</code> → <code>auth/getuserinfo</code> → <code>user/get</code>。</p>

<h2>在线自演示</h2>
<div class="demo">
  <div id="ww_login"></div>
  <div style="flex:1;min-width:260px">
    <p>手机扫码或点二维码下方"模拟扫码"→"确认登录",页面会带 <code>code</code> 回跳到 <code>/wecom/callback</code>,并自动跑通 gettoken → getuserinfo → user/get。</p>
  </div>
</div>
<script src="${origin}/wecom/wwLogin.js"></script>
<script>
  new WwLogin({
    id: "ww_login",
    appid: "wwmockcorpid000000",
    agentid: "1000002",
    redirect_uri: encodeURIComponent("${origin}/wecom/callback"),
    state: "demo-state-123"
  });
</script>

<h2>接入方式(与官方一致)</h2>
<pre>&lt;div id="ww_login"&gt;&lt;/div&gt;
&lt;script src="${origin}/wecom/wwLogin.js"&gt;&lt;/script&gt;
&lt;script&gt;
  new WwLogin({
    id: "ww_login",
    appid: "你的_corpid",
    agentid: "你的_agentid",
    redirect_uri: encodeURIComponent("https://your-app.example/callback"),  // 官方约定:调用方 urlencode;回调会带 ?code=&state=
    state: "任意防伪串",
    redirect_type: ""   // "callback"=iframe 内跳转,默认顶层窗口跳转
  });
&lt;/script&gt;</pre>
<p>新版 <code>@wecom/jssdk</code> 的 <code>ww.createWWLoginPanel({ params: { login_type:"CorpApp", appid, agentid, redirect_uri, state } })</code> 指向的是同一套 qrConnect 与 <code>/cgi-bin/*</code> 接口,把 base URL 换成 <code>${origin}/wecom</code> 即可。</p>

<h2>后端接口(取用户信息三步走)</h2>
<table>
<tr><th>JS SDK</th><td><a href="${origin}/wecom/wwLogin.js"><code>${origin}/wecom/wwLogin.js</code></a></td></tr>
<tr><th>扫码页</th><td><code>${origin}/wecom/sso/qrConnect</code></td></tr>
<tr><th>① 取 access_token</th><td><code>${origin}/wecom/cgi-bin/gettoken?corpid=&amp;corpsecret=</code></td></tr>
<tr><th>② code 换 userid</th><td><code>${origin}/wecom/cgi-bin/auth/getuserinfo?access_token=&amp;code=</code></td></tr>
<tr><th>③ 查成员详情</th><td><code>${origin}/wecom/cgi-bin/user/get?access_token=&amp;userid=</code></td></tr>
<tr><th>(可选)敏感信息</th><td><code>POST ${origin}/wecom/cgi-bin/auth/getuserdetail?access_token=</code>(body: <code>{ "user_ticket": "…" }</code>)</td></tr>
</table>
<pre>curl "${origin}/wecom/cgi-bin/gettoken?corpid=demo&amp;corpsecret=x"
# → { errcode:0, access_token, expires_in }
curl "${origin}/wecom/cgi-bin/auth/getuserinfo?access_token=&lt;AT&gt;&amp;code=&lt;CODE&gt;"
# → { errcode:0, userid, user_ticket }
curl "${origin}/wecom/cgi-bin/user/get?access_token=&lt;AT&gt;&amp;userid=&lt;USERID&gt;"
# → { errcode:0, userid, name, department, mobile, email, ... }</pre>

<h2>固定测试成员</h2>
<table>
<tr><th>userid</th><td><code>${WECOM_MEMBER.userid}</code></td></tr>
<tr><th>name</th><td>${esc(WECOM_MEMBER.name)}</td></tr>
<tr><th>department</th><td><code>[${WECOM_MEMBER.department.join(', ')}]</code></td></tr>
<tr><th>mobile</th><td><code>${WECOM_MEMBER.mobile}</code></td></tr>
</table>
<p><a href="https://authn-cn.pages.dev/">← 返回 authn-cn 文档站</a></p>
</body></html>`
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  })
}

/** 自演示回调:展示 code,并用客户端 fetch 跑通 gettoken → getuserinfo → user/get(CORS 全开)。 */
export function wecomCallback(req: Request, origin: string): Response {
  const q = new URL(req.url).searchParams
  const code = q.get('code') ?? ''
  const state = q.get('state') ?? ''
  const html = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>回调 — Mock 企业微信扫码登录</title>
<style>
  body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;max-width:760px;margin:2.5rem auto;padding:0 1.2rem;line-height:1.7;color:#2c3e50}
  h1{font-size:1.4rem} pre{background:#f6f8fa;border-radius:6px;padding:.9rem;overflow-x:auto;font-size:.82rem;white-space:pre-wrap;word-break:break-all}
  .k{color:#0082ef;font-weight:600} a{color:#0082ef}
</style></head>
<body>
<h1>✅ 企业微信扫码登录回调</h1>
<p><span class="k">code</span> = <code>${esc(code) || '(无)'}</code></p>
<p><span class="k">state</span> = <code>${esc(state) || '(无)'}</code></p>
<h3>gettoken → auth/getuserinfo → user/get</h3>
<pre id="out">处理中…</pre>
<p><a href="/wecom/">← 再试一次</a></p>
<script>
(function () {
  var code = ${JSON.stringify(code)};
  var origin = ${JSON.stringify(origin)};
  var out = document.getElementById("out");
  if (!code) { out.textContent = "没有拿到 code。"; return; }
  var log = "";
  function show(t) { out.textContent = t; }
  fetch(origin + "/wecom/cgi-bin/gettoken?corpid=demo&corpsecret=x")
    .then(function (r) { return r.json(); })
    .then(function (tok) {
      if (tok.errcode) { throw new Error("gettoken: " + JSON.stringify(tok)); }
      log += "① gettoken:\\n" + JSON.stringify(tok, null, 2) + "\\n\\n"; show(log + "② 换 userid…");
      return fetch(origin + "/wecom/cgi-bin/auth/getuserinfo?access_token=" + encodeURIComponent(tok.access_token) + "&code=" + encodeURIComponent(code))
        .then(function (r) { return r.json(); })
        .then(function (ui) {
          if (ui.errcode) { throw new Error("getuserinfo: " + JSON.stringify(ui)); }
          log += "② auth/getuserinfo:\\n" + JSON.stringify(ui, null, 2) + "\\n\\n"; show(log + "③ 查成员详情…");
          return fetch(origin + "/wecom/cgi-bin/user/get?access_token=" + encodeURIComponent(tok.access_token) + "&userid=" + encodeURIComponent(ui.userid))
            .then(function (r) { return r.json(); })
            .then(function (u) { log += "③ user/get:\\n" + JSON.stringify(u, null, 2); show(log); });
        });
    })
    .catch(function (e) { show("出错: " + e.message); });
})();
</script>
</body></html>`
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  })
}
