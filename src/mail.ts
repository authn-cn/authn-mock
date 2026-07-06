/**
 * Mock 邮件服务器。
 *
 * 通过 Cloudflare Email Routing 把投递到本 Worker 的邮件写入 D1,可在线或用 API 查看。
 * 典型用途:联调"邮件一次性验证码(HOTP / email OTP)/ 魔术链接"——被测系统把验证码
 * 发到某个 @<你的域> 地址,测试再用 GET /mail/api/latest?to=… 立即取回验证码。
 *
 * 端点:
 *   GET  /mail/                      —— 在线收件箱(可 ?to= 过滤)
 *   GET  /mail/view/<id>             —— 在线查看单封邮件
 *   GET  /mail/api/messages          —— 列表 JSON(?to= &limit=)
 *   GET  /mail/api/messages/<id>     —— 单封 JSON(含正文)
 *   GET  /mail/api/latest            —— 最新一封 JSON(?to=),含抽取到的 code
 *   POST /mail/api/inject            —— 注入一封"假邮件"(无需真实收信即可联调/演示)
 *   POST /mail/api/clear             —— 清空(?to= 只清该地址)
 *
 * 仅供测试:任何人都能读到投递到这里的邮件,切勿发送真实敏感信息。
 */

export interface Message {
  id: string
  to_addr: string
  from_addr: string | null
  subject: string | null
  text_body: string | null
  html_body: string | null
  code: string | null
  received_at: number
  raw_size: number | null
}

/** 收件箱保留时长:超过则在下次写入时清理(mock 自净)。 */
const RETENTION_MS = 24 * 60 * 60 * 1000

export interface MailStore {
  insert(m: Message): Promise<void>
  list(to: string | null, limit: number): Promise<Message[]>
  get(id: string): Promise<Message | null>
  latest(to: string | null): Promise<Message | null>
  clear(to: string | null): Promise<number>
}

/** D1 实现。 */
export function d1Store(db: D1Database): MailStore {
  return {
    async insert(m) {
      await db
        .prepare(
          `INSERT INTO messages (id, to_addr, from_addr, subject, text_body, html_body, code, received_at, raw_size)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(m.id, m.to_addr, m.from_addr, m.subject, m.text_body, m.html_body, m.code, m.received_at, m.raw_size)
        .run()
      await db.prepare(`DELETE FROM messages WHERE received_at < ?`).bind(m.received_at - RETENTION_MS).run()
    },
    async list(to, limit) {
      const lim = Math.min(Math.max(limit, 1), 200)
      const stmt = to
        ? db
            .prepare(
              `SELECT id, to_addr, from_addr, subject, code, received_at, raw_size
               FROM messages WHERE to_addr = ? ORDER BY received_at DESC LIMIT ?`,
            )
            .bind(to.toLowerCase(), lim)
        : db
            .prepare(
              `SELECT id, to_addr, from_addr, subject, code, received_at, raw_size
               FROM messages ORDER BY received_at DESC LIMIT ?`,
            )
            .bind(lim)
      const { results } = await stmt.all<Message>()
      return results ?? []
    },
    async get(id) {
      return (await db.prepare(`SELECT * FROM messages WHERE id = ?`).bind(id).first<Message>()) ?? null
    },
    async latest(to) {
      const stmt = to
        ? db.prepare(`SELECT * FROM messages WHERE to_addr = ? ORDER BY received_at DESC LIMIT 1`).bind(to.toLowerCase())
        : db.prepare(`SELECT * FROM messages ORDER BY received_at DESC LIMIT 1`)
      return (await stmt.first<Message>()) ?? null
    },
    async clear(to) {
      const stmt = to
        ? db.prepare(`DELETE FROM messages WHERE to_addr = ?`).bind(to.toLowerCase())
        : db.prepare(`DELETE FROM messages`)
      const res = await stmt.run()
      return res.meta.changes ?? 0
    },
  }
}

/** 从主题/正文中抽取一次性验证码(优先带 code/验证码 等提示词的数字,退化为独立数字串)。 */
export function extractCode(subject: string | null, text: string | null): string | null {
  const hay = `${subject ?? ''}\n${text ?? ''}`
  const labeled = /(?:code|otp|passcode|pin|one[-\s]?time|验证码|校验码|动态码|verification code)\D{0,20}(\d{4,10})/i.exec(hay)
  if (labeled) return labeled[1]
  const bare = /(?<!\d)(\d{4,10})(?!\d)/.exec(hay)
  return bare ? bare[1] : null
}

/** 把解析后的邮件字段组装成一条待入库的消息。 */
export function buildMessage(input: {
  to: string
  from?: string | null
  subject?: string | null
  text?: string | null
  html?: string | null
  rawSize?: number | null
  id?: string
  receivedAt?: number
}): Message {
  const subject = input.subject ?? null
  const text = input.text ?? null
  return {
    id: input.id ?? crypto.randomUUID(),
    to_addr: input.to.toLowerCase(),
    from_addr: input.from ?? null,
    subject,
    text_body: text,
    html_body: input.html ?? null,
    code: extractCode(subject, text),
    received_at: input.receivedAt ?? Date.now(),
    raw_size: input.rawSize ?? null,
  }
}

/**
 * 接收 Email Routing 投递的邮件并入库。message 为 Cloudflare ForwardableEmailMessage。
 * 用 postal-mime 解析 MIME,取出主题与正文。
 */
export async function receiveEmail(message: ForwardableEmailMessage, store: MailStore): Promise<void> {
  const { default: PostalMime } = await import('postal-mime')
  const buf = await new Response(message.raw).arrayBuffer()
  const parsed = await PostalMime.parse(buf)
  await store.insert(
    buildMessage({
      to: message.to,
      from: message.from,
      subject: parsed.subject ?? null,
      text: parsed.text ?? null,
      html: parsed.html ?? null,
      rawSize: message.rawSize,
    }),
  )
}

// ---------- HTTP ----------

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
    },
  })
}

function esc(s: unknown): string {
  return String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!)
}

const STYLE = `body{font-family:-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;max-width:820px;margin:2.5rem auto;padding:0 1.2rem;line-height:1.6;color:#2c3e50}
h1{font-size:1.5rem}code{font-family:ui-monospace,monospace;background:#f6f8fa;padding:.1rem .35rem;border-radius:4px;font-size:.88em}
.warn{background:#fff3cd;border-left:4px solid #e0a800;padding:.6rem 1rem;border-radius:4px;font-size:.9rem}
table{border-collapse:collapse;width:100%;font-size:.9rem;margin-top:1rem}th,td{border:1px solid #dfe2e5;padding:.45rem .7rem;text-align:left;vertical-align:top}
a{color:#3eaf7c}.code{font-weight:700;color:#c0392b}.muted{color:#888;font-size:.85rem}
form.bar{margin:1rem 0}input[type=text]{padding:.4rem .6rem;border:1px solid #dfe2e5;border-radius:6px;min-width:16rem}
button{padding:.4rem .9rem;border:1px solid #3eaf7c;background:#3eaf7c;color:#fff;border-radius:6px;cursor:pointer}
pre{background:#f6f8fa;padding:.8rem;border-radius:6px;overflow:auto;font-size:.8rem;white-space:pre-wrap;word-break:break-word}
iframe{width:100%;height:420px;border:1px solid #dfe2e5;border-radius:6px;background:#fff}`

function page(title: string, bodyHtml: string): Response {
  return new Response(
    `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title>
<style>${STYLE}</style></head><body>${bodyHtml}</body></html>`,
    { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } },
  )
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')
}

/** 处理 /mail/* 的所有请求。返回 null 表示不是本模块的路径。 */
export async function handleMail(req: Request, url: URL, store: MailStore): Promise<Response | null> {
  const path = url.pathname
  const to = url.searchParams.get('to')

  // ---- API ----
  if (path === '/mail/api/messages') {
    const limit = parseInt(url.searchParams.get('limit') || '50', 10) || 50
    return json({ messages: await store.list(to, limit) })
  }
  if (path.startsWith('/mail/api/messages/')) {
    const id = decodeURIComponent(path.slice('/mail/api/messages/'.length))
    const m = await store.get(id)
    return m ? json(m) : json({ error: 'not found' }, 404)
  }
  if (path === '/mail/api/latest') {
    const m = await store.latest(to)
    return m ? json(m) : json({ error: 'inbox empty', to: to ?? '(any)' }, 404)
  }
  if (path === '/mail/api/inject') {
    if (req.method !== 'POST') return json({ error: 'need POST' }, 405)
    let b: Record<string, unknown>
    try {
      const ct = req.headers.get('Content-Type') || ''
      b = ct.includes('application/json') ? await req.json() : Object.fromEntries(new URLSearchParams(await req.text()))
    } catch {
      return json({ error: 'bad body' }, 400)
    }
    if (!b.to) return json({ error: 'to 必填' }, 400)
    const m = buildMessage({
      to: String(b.to),
      from: b.from ? String(b.from) : 'inject@authn-mock.local',
      subject: b.subject != null ? String(b.subject) : null,
      text: b.text != null ? String(b.text) : null,
      html: b.html != null ? String(b.html) : null,
    })
    await store.insert(m)
    return json({ ok: true, id: m.id, code: m.code })
  }
  if (path === '/mail/api/clear') {
    if (req.method !== 'POST') return json({ error: 'need POST' }, 405)
    return json({ ok: true, deleted: await store.clear(to) })
  }

  // ---- 在线查看 ----
  if (path.startsWith('/mail/view/')) {
    const id = decodeURIComponent(path.slice('/mail/view/'.length))
    const m = await store.get(id)
    if (!m) return page('邮件未找到', `<h1>邮件未找到</h1><p><a href="/mail/">← 返回收件箱</a></p>`)
    const bodyBlock = m.html_body
      ? `<p class="muted">HTML 正文(sandbox 渲染):</p><iframe sandbox srcdoc="${esc(m.html_body)}"></iframe>`
      : `<pre>${esc(m.text_body || '(无正文)')}</pre>`
    return page(
      m.subject || '(无主题)',
      `<p><a href="/mail/">← 返回收件箱</a></p>
<h1>${esc(m.subject || '(无主题)')}</h1>
<table><tbody>
<tr><th>From</th><td>${esc(m.from_addr)}</td></tr>
<tr><th>To</th><td>${esc(m.to_addr)}</td></tr>
<tr><th>时间</th><td>${fmtTime(m.received_at)}</td></tr>
${m.code ? `<tr><th>抽取到的验证码</th><td class="code">${esc(m.code)}</td></tr>` : ''}
</tbody></table>
${bodyBlock}
<p class="muted">JSON:<a href="/mail/api/messages/${encodeURIComponent(m.id)}">/mail/api/messages/${esc(m.id)}</a></p>`,
    )
  }

  // ---- 在线收件箱 ----
  if (path === '/mail/' || path === '/mail') {
    const rows = await store.list(to, 100)
    const list = rows.length
      ? rows
          .map(
            (m) => `<tr>
<td>${fmtTime(m.received_at)}</td>
<td>${esc(m.from_addr)}</td>
<td>${esc(m.to_addr)}</td>
<td><a href="/mail/view/${encodeURIComponent(m.id)}">${esc(m.subject || '(无主题)')}</a></td>
<td class="code">${esc(m.code || '')}</td>
</tr>`,
          )
          .join('')
      : `<tr><td colspan="5" class="muted">收件箱为空。${to ? `没有发给 <code>${esc(to)}</code> 的邮件。` : ''}</td></tr>`
    return page(
      'Mock 邮件收件箱',
      `<h1>📬 Mock 邮件收件箱</h1>
<p class="warn"><strong>仅供测试。</strong>投递到这里的任何邮件都可被任何人读取,切勿发送真实敏感信息。收件保留 24 小时。</p>
<p>用 Cloudflare Email Routing 把某个地址路由到本服务;发到该地址的邮件会出现在下面。也可 <code>POST /mail/api/inject</code> 注入假邮件联调。</p>
<form class="bar" method="get" action="/mail/">
<input type="text" name="to" value="${esc(to || '')}" placeholder="按收件地址过滤,如 otp@authn.tech" />
<button type="submit">过滤</button>
</form>
<table><thead><tr><th>时间(UTC)</th><th>From</th><th>To</th><th>主题</th><th>验证码</th></tr></thead>
<tbody>${list}</tbody></table>
<p class="muted">API:<code>GET /mail/api/messages?to=</code> · <code>GET /mail/api/latest?to=</code> · <code>POST /mail/api/inject</code></p>`,
    )
  }

  return null
}
