import { describe, expect, it } from 'vitest'
import worker from '../src/index'

const ORIGIN = 'https://mock.test'

async function call(path: string, init?: RequestInit): Promise<Response> {
  return worker.fetch(new Request(ORIGIN + path, init))
}

describe('mock wechat — JS SDK', () => {
  it('serves a WxLogin SDK pointing at this origin', async () => {
    const res = await call('/wechat/wxLogin.js')
    expect(res.status).toBe(200)
    expect(res.headers.get('Content-Type')).toContain('javascript')
    const js = await res.text()
    expect(js).toContain('function WxLogin')
    expect(js).toContain('global.WxLogin = WxLogin')
    expect(js).toContain(`${ORIGIN}/connect/qrconnect`)
  })
})

describe('mock wechat — scan-to-login flow', () => {
  async function runFlow(): Promise<{ code: string; state: string }> {
    // 1) 内嵌二维码页(与真实 open.weixin.qq.com/connect/qrconnect 同参数)
    const redirectUri = 'https://app.test/wx/cb'
    const qr = await call(
      `/connect/qrconnect?appid=wxdemo&scope=snsapi_login&redirect_uri=${encodeURIComponent(
        redirectUri,
      )}&state=st-1&self_redirect=false`,
    )
    expect(qr.status).toBe(200)
    const html = await qr.text()
    const ticket = /\/wechat\/scan\?ticket=([a-f0-9]+)/.exec(html)?.[1]
    expect(ticket).toBeTruthy()

    // 2) 扫码前:轮询应为 PENDING
    expect(await (await call(`/connect/poll?ticket=${ticket}`)).json()).toEqual({ status: 'PENDING' })

    // 3) "手机端"确认登录
    const confirm = await call(`/wechat/scan?ticket=${ticket}&action=confirm`)
    expect(confirm.status).toBe(200)

    // 4) 轮询拿到 code
    const polled: any = await (await call(`/connect/poll?ticket=${ticket}`)).json()
    expect(polled.status).toBe('CONFIRMED')
    expect(polled.code).toBeTruthy()
    return { code: polled.code, state: 'st-1' }
  }

  it('exchanges code for token, then userinfo — with WeChat-shaped fields', async () => {
    const { code } = await runFlow()

    const tok: any = await (
      await call(`/sns/oauth2/access_token?appid=demo&secret=x&code=${encodeURIComponent(code)}&grant_type=authorization_code`)
    ).json()
    expect(tok.access_token).toBeTruthy()
    expect(tok.refresh_token).toBeTruthy()
    expect(tok.expires_in).toBe(7200)
    expect(tok.openid).toBe('mock-openid-oWx0000000000000000000')
    expect(tok.unionid).toBeTruthy()

    const ui: any = await (
      await call(`/sns/userinfo?access_token=${encodeURIComponent(tok.access_token)}&openid=${tok.openid}`)
    ).json()
    expect(ui).toMatchObject({
      openid: 'mock-openid-oWx0000000000000000000',
      nickname: '微信测试用户',
      country: 'CN',
    })
    expect(Array.isArray(ui.privilege)).toBe(true)

    // /sns/auth 校验通过
    expect(await (await call(`/sns/auth?access_token=${encodeURIComponent(tok.access_token)}&openid=${tok.openid}`)).json()).toEqual({
      errcode: 0,
      errmsg: 'ok',
    })
  })

  it('refresh_token grant returns a fresh access_token', async () => {
    const { code } = await runFlow()
    const tok: any = await (
      await call(`/sns/oauth2/access_token?appid=demo&secret=x&code=${encodeURIComponent(code)}&grant_type=authorization_code`)
    ).json()
    const refreshed: any = await (
      await call(`/sns/oauth2/refresh_token?appid=demo&grant_type=refresh_token&refresh_token=${encodeURIComponent(tok.refresh_token)}`)
    ).json()
    expect(refreshed.access_token).toBeTruthy()
    expect(refreshed.openid).toBe(tok.openid)
  })

  it('cancelling marks the ticket cancelled', async () => {
    const redirectUri = 'https://app.test/wx/cb'
    const qr = await call(
      `/connect/qrconnect?appid=wxdemo&redirect_uri=${encodeURIComponent(redirectUri)}&state=s`,
    )
    const ticket = /\/wechat\/scan\?ticket=([a-f0-9]+)/.exec(await qr.text())?.[1]
    await call(`/wechat/scan?ticket=${ticket}&action=cancel`)
    expect(await (await call(`/connect/poll?ticket=${ticket}`)).json()).toEqual({ status: 'CANCELLED' })
  })
})

describe('mock wechat — error shapes (WeChat {errcode,errmsg})', () => {
  it('rejects an invalid code', async () => {
    const res: any = await (
      await call('/sns/oauth2/access_token?appid=demo&secret=x&code=bogus&grant_type=authorization_code')
    ).json()
    expect(res.errcode).toBe(40029)
  })

  it('rejects an invalid access_token on userinfo', async () => {
    const res: any = await (await call('/sns/userinfo?access_token=bogus&openid=x')).json()
    expect(res.errcode).toBe(40001)
  })

  it('rejects unsupported grant_type', async () => {
    const res: any = await (
      await call('/sns/oauth2/access_token?code=x&grant_type=password')
    ).json()
    expect(res.errcode).toBe(40002)
  })
})
