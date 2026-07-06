import { describe, expect, it } from 'vitest'
import { buildMessage, extractCode, handleMail, type MailStore, type Message } from '../src/mail'

const ORIGIN = 'https://mock.test'

/** 内存版 MailStore,避免在单元测试里依赖 D1。 */
function memStore(): MailStore {
  let rows: Message[] = []
  return {
    async insert(m) {
      rows.unshift(m)
    },
    async list(to, limit) {
      return rows.filter((r) => !to || r.to_addr === to.toLowerCase()).slice(0, limit)
    },
    async get(id) {
      return rows.find((r) => r.id === id) ?? null
    },
    async latest(to) {
      return rows.filter((r) => !to || r.to_addr === to.toLowerCase())[0] ?? null
    },
    async clear(to) {
      const before = rows.length
      rows = rows.filter((r) => (to ? r.to_addr !== to.toLowerCase() : false))
      return before - rows.length
    },
  }
}

function call(store: MailStore, path: string, init?: RequestInit) {
  const url = new URL(ORIGIN + path)
  return handleMail(new Request(url, init), url, store)
}

describe('extractCode', () => {
  it('prefers a labeled code', () => {
    expect(extractCode('登录验证码', '你的验证码是 483920,5 分钟内有效')).toBe('483920')
    expect(extractCode(null, 'Your verification code: 12345')).toBe('12345')
  })
  it('falls back to a bare digit group', () => {
    expect(extractCode('Order #7788 shipped', 'left the warehouse 4210')).toBe('7788')
  })
  it('returns null when no digits', () => {
    expect(extractCode('hi', 'welcome aboard')).toBeNull()
  })
})

describe('buildMessage', () => {
  it('lowercases recipient and extracts code', () => {
    const m = buildMessage({ to: 'Alice@Mail.Test', subject: '验证码', text: 'code 998877' })
    expect(m.to_addr).toBe('alice@mail.test')
    expect(m.code).toBe('998877')
    expect(m.id).toMatch(/[0-9a-f-]{36}/)
  })
})

describe('handleMail HTTP', () => {
  it('inject → list → get → latest → clear', async () => {
    const store = memStore()

    const injected = await call(store, '/mail/api/inject', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ to: 'alice@mail.test', subject: 'OTP', text: 'code 246810' }),
    })
    expect(injected!.status).toBe(200)
    const { id, code } = await injected!.json<{ id: string; code: string }>()
    expect(code).toBe('246810')

    const list = await (await call(store, '/mail/api/messages?to=alice@mail.test'))!.json<{ messages: Message[] }>()
    expect(list.messages).toHaveLength(1)

    const single = await call(store, `/mail/api/messages/${id}`)
    expect((await single!.json<Message>()).text_body).toContain('246810')

    const latest = await call(store, '/mail/api/latest?to=alice@mail.test')
    expect((await latest!.json<Message>()).id).toBe(id)

    const cleared = await call(store, '/mail/api/clear?to=alice@mail.test', { method: 'POST' })
    expect((await cleared!.json<{ deleted: number }>()).deleted).toBe(1)

    const empty = await call(store, '/mail/api/latest?to=alice@mail.test')
    expect(empty!.status).toBe(404)
  })

  it('inject requires to', async () => {
    const res = await call(memStore(), '/mail/api/inject', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    })
    expect(res!.status).toBe(400)
  })

  it('requires a specific recipient for list/latest/clear', async () => {
    const store = memStore()
    expect((await call(store, '/mail/api/messages'))!.status).toBe(400)
    expect((await call(store, '/mail/api/latest'))!.status).toBe(400)
    expect((await call(store, '/mail/api/clear', { method: 'POST' }))!.status).toBe(400)
  })

  it('inbox without to shows only a search box (no full list)', async () => {
    const store = memStore()
    await call(store, '/mail/api/inject', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ to: 'someone@authn.tech', subject: 'secret', text: 'hi' }),
    })
    const html = await (await call(store, '/mail/'))!.text()
    expect(html).toContain('Mock 邮件收件箱')
    expect(html).not.toContain('secret') // 不泄露任何具体邮件
  })

  it('returns null for non-mail paths', async () => {
    expect(await call(memStore(), '/mail-other')).toBeNull()
  })
})
