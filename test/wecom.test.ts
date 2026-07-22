import { describe, expect, it } from 'vitest'
import worker from '../src/index'

const ORIGIN = 'https://mock.test'

async function call(path: string, init?: RequestInit): Promise<Response> {
  return worker.fetch(new Request(ORIGIN + path, init))
}

describe('mock wecom — JS SDK', () => {
  it('serves a WwLogin SDK pointing at this origin', async () => {
    const res = await call('/wecom/wwLogin.js')
    expect(res.status).toBe(200)
    expect(res.headers.get('Content-Type')).toContain('javascript')
    const js = await res.text()
    expect(js).toContain('function WwLogin')
    expect(js).toContain('global.WwLogin = WwLogin')
    expect(js).toContain(`${ORIGIN}/wecom/sso/qrConnect`)
  })
})

describe('mock wecom — scan-to-login + three-step userinfo', () => {
  async function scanToCode(): Promise<string> {
    const redirectUri = 'https://app.test/ww/cb'
    const qr = await call(
      `/wecom/sso/qrConnect?appid=wwcorp&agentid=1000002&redirect_uri=${encodeURIComponent(
        redirectUri,
      )}&state=st-1`,
    )
    expect(qr.status).toBe(200)
    const ticket = /\/wecom\/scan\?ticket=([a-f0-9]+)/.exec(await qr.text())?.[1]
    expect(ticket).toBeTruthy()

    expect(await (await call(`/wecom/sso/poll?ticket=${ticket}`)).json()).toEqual({ status: 'PENDING' })

    await call(`/wecom/scan?ticket=${ticket}&action=confirm`)
    const polled: any = await (await call(`/wecom/sso/poll?ticket=${ticket}`)).json()
    expect(polled.status).toBe('CONFIRMED')
    return polled.code
  }

  it('runs gettoken → auth/getuserinfo → user/get and returns the fixed member', async () => {
    const code = await scanToCode()

    // ① 应用级 access_token
    const tok: any = await (await call('/wecom/cgi-bin/gettoken?corpid=demo&corpsecret=x')).json()
    expect(tok.errcode).toBe(0)
    expect(tok.access_token).toBeTruthy()
    expect(tok.expires_in).toBe(7200)

    // ② code 换 userid + user_ticket
    const ui: any = await (
      await call(`/wecom/cgi-bin/auth/getuserinfo?access_token=${encodeURIComponent(tok.access_token)}&code=${encodeURIComponent(code)}`)
    ).json()
    expect(ui.errcode).toBe(0)
    expect(ui.userid).toBe('zhangsan')
    expect(ui.user_ticket).toBeTruthy()

    // ③ userid 查成员详情
    const member: any = await (
      await call(`/wecom/cgi-bin/user/get?access_token=${encodeURIComponent(tok.access_token)}&userid=${ui.userid}`)
    ).json()
    expect(member).toMatchObject({ errcode: 0, userid: 'zhangsan', name: '张三', mobile: '13800000000' })
    expect(member.department).toEqual([1])

    // (可选)user_ticket 查敏感信息
    const detail: any = await (
      await call(`/wecom/cgi-bin/auth/getuserdetail?access_token=${encodeURIComponent(tok.access_token)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_ticket: ui.user_ticket }),
      })
    ).json()
    expect(detail).toMatchObject({ errcode: 0, userid: 'zhangsan', gender: '1' })
  })
})

describe('mock wecom — error shapes ({errcode,errmsg})', () => {
  it('rejects missing corpid on gettoken', async () => {
    expect((await (await call('/wecom/cgi-bin/gettoken?corpsecret=x')).json() as any).errcode).toBe(40013)
  })

  it('rejects an invalid access_token', async () => {
    const res: any = await (await call('/wecom/cgi-bin/user/get?access_token=bogus&userid=zhangsan')).json()
    expect(res.errcode).toBe(40014)
  })

  it('rejects an invalid code on getuserinfo', async () => {
    const tok: any = await (await call('/wecom/cgi-bin/gettoken?corpid=demo&corpsecret=x')).json()
    const res: any = await (
      await call(`/wecom/cgi-bin/auth/getuserinfo?access_token=${encodeURIComponent(tok.access_token)}&code=bogus`)
    ).json()
    expect(res.errcode).toBe(40029)
  })

  it('rejects an unknown userid on user/get', async () => {
    const tok: any = await (await call('/wecom/cgi-bin/gettoken?corpid=demo&corpsecret=x')).json()
    const res: any = await (
      await call(`/wecom/cgi-bin/user/get?access_token=${encodeURIComponent(tok.access_token)}&userid=nobody`)
    ).json()
    expect(res.errcode).toBe(60111)
  })
})
