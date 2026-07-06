import { describe, expect, it } from 'vitest'
import worker from '../src/index'
import { parseFilter, matchFilter, DIRECTORY, type Entry } from '../src/ldap'

const ORIGIN = 'https://mock.test'
const alice = DIRECTORY.find((e) => e.dn.startsWith('uid=alice')) as Entry

function m(filter: string, entry: Entry) {
  return matchFilter(parseFilter(filter), entry)
}

describe('RFC 4515 filter', () => {
  it('equality (case-insensitive)', () => {
    expect(m('(uid=alice)', alice)).toBe(true)
    expect(m('(uid=ALICE)', alice)).toBe(true)
    expect(m('(uid=bob)', alice)).toBe(false)
  })
  it('present', () => {
    expect(m('(mail=*)', alice)).toBe(true)
    expect(m('(nonexistent=*)', alice)).toBe(false)
  })
  it('substring', () => {
    expect(m('(cn=Alice*)', alice)).toBe(true)
    expect(m('(mail=*@example.com)', alice)).toBe(true)
    expect(m('(cn=*Zh*)', alice)).toBe(true)
    expect(m('(cn=*xyz*)', alice)).toBe(false)
  })
  it('and / or / not', () => {
    expect(m('(&(objectClass=person)(departmentNumber=eng))', alice)).toBe(true)
    expect(m('(&(objectClass=person)(departmentNumber=design))', alice)).toBe(false)
    expect(m('(|(uid=bob)(uid=alice))', alice)).toBe(true)
    expect(m('(!(uid=bob))', alice)).toBe(true)
  })
  it('rejects malformed filters', () => {
    expect(() => parseFilter('(uid=alice')).toThrow()
    expect(() => parseFilter('uid=alice)')).toThrow()
    expect(() => parseFilter('(&)')).toThrow()
  })
})

describe('/ldap/search', () => {
  const call = (qs: string) => worker.fetch(new Request(`${ORIGIN}/ldap/search?${qs}`))

  it('sub scope with AND filter', async () => {
    const res = await call('base=dc=example,dc=com&scope=sub&filter=' + encodeURIComponent('(&(objectClass=person)(departmentNumber=eng))'))
    const body = await res.json()
    expect(body.count).toBe(2)
    expect(body.entries.map((e: Entry) => e.attributes.uid[0]).sort()).toEqual(['alice', 'bob'])
  })

  it('one scope lists only direct children', async () => {
    const res = await call('base=dc=example,dc=com&scope=one&filter=' + encodeURIComponent('(objectClass=*)'))
    const body = await res.json()
    // ou=people, ou=groups(直接子级),不含 uid=alice(孙级)
    expect(body.entries.map((e: Entry) => e.dn)).toContain('ou=people,dc=example,dc=com')
    expect(body.entries.map((e: Entry) => e.dn)).not.toContain('uid=alice,ou=people,dc=example,dc=com')
  })

  it('attribute projection', async () => {
    const res = await call('base=ou=people,dc=example,dc=com&filter=' + encodeURIComponent('(uid=carol)') + '&attributes=mail,uid')
    const body = await res.json()
    expect(body.count).toBe(1)
    expect(Object.keys(body.entries[0].attributes).sort()).toEqual(['mail', 'uid'])
  })

  it('400 on bad filter', async () => {
    const res = await call('filter=' + encodeURIComponent('(uid=alice'))
    expect(res.status).toBe(400)
  })
})
