/**
 * Mock LDAP 目录(HTTP/JSON 搜索模拟器)。
 *
 * 说明:LDAP 是 TCP(389/636)上的 ASN.1/BER 二进制协议,Cloudflare Workers 无法
 * 监听 TCP,故这里不是真正的 LDAP 协议服务器,而是一个"目录搜索模拟器":用 HTTP/JSON
 * 暴露一个固定的示例目录,并按 RFC 4515 过滤器求值,便于联调过滤器与搜索语义。
 *
 * 端点:
 *   GET /ldap/            —— 说明页(HTML)
 *   GET /ldap/entries     —— 返回整个示例目录(JSON)
 *   GET /ldap/search?base=&scope=&filter=&attributes=
 *                         —— 按 base(DN)、scope(base|one|sub)、RFC 4515 filter 搜索
 *
 * 仅供测试。
 */

export interface Entry {
  dn: string
  attributes: Record<string, string[]>
}

// 固定示例目录:dc=example,dc=com
export const DIRECTORY: Entry[] = [
  { dn: 'dc=example,dc=com', attributes: { objectClass: ['top', 'domain'], dc: ['example'] } },
  { dn: 'ou=people,dc=example,dc=com', attributes: { objectClass: ['top', 'organizationalUnit'], ou: ['people'] } },
  { dn: 'ou=groups,dc=example,dc=com', attributes: { objectClass: ['top', 'organizationalUnit'], ou: ['groups'] } },
  {
    dn: 'uid=alice,ou=people,dc=example,dc=com',
    attributes: {
      objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
      uid: ['alice'], cn: ['Alice Zhang'], sn: ['Zhang'], givenName: ['Alice'],
      mail: ['alice@example.com'], title: ['Engineer'], departmentNumber: ['eng'],
      telephoneNumber: ['+86-10-1000-0001'], employeeType: ['fulltime'],
    },
  },
  {
    dn: 'uid=bob,ou=people,dc=example,dc=com',
    attributes: {
      objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
      uid: ['bob'], cn: ['Bob Li'], sn: ['Li'], givenName: ['Bob'],
      mail: ['bob@example.com'], title: ['Manager'], departmentNumber: ['eng'],
      telephoneNumber: ['+86-10-1000-0002'], employeeType: ['fulltime'],
    },
  },
  {
    dn: 'uid=carol,ou=people,dc=example,dc=com',
    attributes: {
      objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
      uid: ['carol'], cn: ['Carol Wang'], sn: ['Wang'], givenName: ['Carol'],
      mail: ['carol@example.org'], title: ['Designer'], departmentNumber: ['design'],
      telephoneNumber: ['+86-10-1000-0003'], employeeType: ['contractor'],
    },
  },
  {
    dn: 'cn=admins,ou=groups,dc=example,dc=com',
    attributes: {
      objectClass: ['top', 'groupOfNames'], cn: ['admins'],
      member: ['uid=alice,ou=people,dc=example,dc=com'],
    },
  },
  {
    dn: 'cn=developers,ou=groups,dc=example,dc=com',
    attributes: {
      objectClass: ['top', 'groupOfNames'], cn: ['developers'],
      member: ['uid=alice,ou=people,dc=example,dc=com', 'uid=bob,ou=people,dc=example,dc=com'],
    },
  },
]

// ---------- RFC 4515 过滤器 ----------

type Node =
  | { op: '&' | '|'; children: Node[] }
  | { op: '!'; child: Node }
  | { op: 'present'; attr: string }
  | { op: 'eq' | 'ge' | 'le' | 'approx'; attr: string; value: string }
  | { op: 'sub'; attr: string; init: string; any: string[]; final: string }

class FilterError extends Error {}

/** 解析 RFC 4515 过滤器字符串为 AST。 */
export function parseFilter(input: string): Node {
  const s = input.trim()
  let i = 0
  const peek = () => s[i]
  const err = (m: string) => {
    throw new FilterError(`过滤器语法错误(位置 ${i}):${m}`)
  }

  function parseExpr(): Node {
    if (peek() !== '(') err("期望 '('")
    i++ // (
    let node: Node
    const c = peek()
    if (c === '&' || c === '|') {
      i++
      const children: Node[] = []
      while (peek() === '(') children.push(parseExpr())
      if (children.length === 0) err('& / | 至少需要一个子过滤器')
      node = { op: c, children }
    } else if (c === '!') {
      i++
      node = { op: '!', child: parseExpr() }
    } else {
      node = parseItem()
    }
    if (peek() !== ')') err("期望 ')'")
    i++ // )
    return node
  }

  function parseItem(): Node {
    // attr [ >= | <= | ~= | = ] value  ;  value 可含 * 表示子串/present
    let attr = ''
    while (i < s.length && !'()<>~='.includes(s[i])) attr += s[i++]
    attr = attr.trim()
    if (!attr) err('缺少属性名')
    let op: 'eq' | 'ge' | 'le' | 'approx' = 'eq'
    if (s[i] === '>' && s[i + 1] === '=') { op = 'ge'; i += 2 }
    else if (s[i] === '<' && s[i + 1] === '=') { op = 'le'; i += 2 }
    else if (s[i] === '~' && s[i + 1] === '=') { op = 'approx'; i += 2 }
    else if (s[i] === '=') { op = 'eq'; i += 1 }
    else err('缺少比较符(= >= <= ~=)')
    let value = ''
    while (i < s.length && s[i] !== ')') value += s[i++]

    if (op === 'eq') {
      if (value === '*') return { op: 'present', attr }
      if (value.includes('*')) {
        const parts = value.split('*')
        return { op: 'sub', attr, init: parts[0], any: parts.slice(1, -1), final: parts[parts.length - 1] }
      }
    }
    return { op, attr, value }
  }

  const root = parseExpr()
  if (i !== s.length) err('过滤器末尾有多余字符')
  return root
}

function unescape(v: string): string {
  // RFC 4515 转义:\28 \29 \2a \5c 等
  return v.replace(/\\([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
}

function valuesOf(entry: Entry, attr: string): string[] {
  const key = Object.keys(entry.attributes).find((k) => k.toLowerCase() === attr.toLowerCase())
  return key ? entry.attributes[key] : []
}

/** 判断某条目是否匹配过滤器。 */
export function matchFilter(node: Node, entry: Entry): boolean {
  switch (node.op) {
    case '&':
      return node.children.every((c) => matchFilter(c, entry))
    case '|':
      return node.children.some((c) => matchFilter(c, entry))
    case '!':
      return !matchFilter(node.child, entry)
    case 'present':
      return valuesOf(entry, node.attr).length > 0
    case 'eq': {
      const v = unescape(node.value).toLowerCase()
      return valuesOf(entry, node.attr).some((x) => x.toLowerCase() === v)
    }
    case 'approx': {
      // 近似匹配没有标准算法,这里等同于大小写不敏感相等
      const v = unescape(node.value).toLowerCase()
      return valuesOf(entry, node.attr).some((x) => x.toLowerCase() === v)
    }
    case 'ge': {
      const v = unescape(node.value)
      return valuesOf(entry, node.attr).some((x) => x.localeCompare(v) >= 0)
    }
    case 'le': {
      const v = unescape(node.value)
      return valuesOf(entry, node.attr).some((x) => x.localeCompare(v) <= 0)
    }
    case 'sub': {
      const init = unescape(node.init).toLowerCase()
      const fin = unescape(node.final).toLowerCase()
      const anys = node.any.map((a) => unescape(a).toLowerCase())
      return valuesOf(entry, node.attr).some((raw) => {
        let x = raw.toLowerCase()
        if (init && !x.startsWith(init)) return false
        x = x.slice(init.length)
        for (const a of anys) {
          const idx = x.indexOf(a)
          if (idx < 0) return false
          x = x.slice(idx + a.length)
        }
        return fin ? x.endsWith(fin) : true
      })
    }
  }
}

// ---------- DN / scope ----------

function normDn(dn: string): string {
  return dn.split(',').map((p) => p.trim().toLowerCase()).join(',')
}

/** 条目 dn 是否在 base 之下(sub:含 base 及所有后代;one:仅直接子级;base:仅自身)。 */
function inScope(dn: string, base: string, scope: string): boolean {
  const d = normDn(dn)
  const b = normDn(base)
  if (scope === 'base') return d === b
  if (d === b) return false
  if (!d.endsWith(',' + b)) return false
  if (scope === 'one') {
    const prefix = d.slice(0, d.length - b.length - 1)
    return !prefix.includes(',') // 只差一个 RDN
  }
  return true // sub
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

export function ldapSearch(req: Request): Response {
  const p = new URL(req.url).searchParams
  const base = p.get('base') || 'dc=example,dc=com'
  const scope = (p.get('scope') || 'sub').toLowerCase()
  const filterStr = p.get('filter') || '(objectClass=*)'
  if (!['base', 'one', 'sub'].includes(scope)) return json({ error: 'scope 必须是 base|one|sub' }, 400)

  let ast: Node
  try {
    ast = parseFilter(filterStr)
  } catch (e) {
    return json({ error: (e as Error).message, filter: filterStr }, 400)
  }

  const wanted = (p.get('attributes') || '').split(',').map((a) => a.trim()).filter(Boolean)
  const results = DIRECTORY.filter((e) => inScope(e.dn, base, scope) && matchFilter(ast, e)).map((e) => {
    if (!wanted.length) return e
    const attrs: Record<string, string[]> = {}
    for (const a of wanted) {
      const key = Object.keys(e.attributes).find((k) => k.toLowerCase() === a.toLowerCase())
      if (key) attrs[key] = e.attributes[key]
    }
    return { dn: e.dn, attributes: attrs }
  })

  return json({ base, scope, filter: filterStr, count: results.length, entries: results })
}

export function ldapEntries(): Response {
  return json({ count: DIRECTORY.length, entries: DIRECTORY })
}

export function ldapHome(issuer: string): Response {
  const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Authn Mock — LDAP</title>
<style>body{font-family:-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;max-width:760px;margin:2.5rem auto;padding:0 1.2rem;line-height:1.7;color:#2c3e50}
h1{font-size:1.5rem}code,pre{font-family:ui-monospace,monospace;background:#f6f8fa;border-radius:4px}code{padding:.15rem .4rem}pre{padding:.9rem;overflow-x:auto;font-size:.85rem}
.warn{background:#fff3cd;border-left:4px solid #e0a800;padding:.7rem 1rem;border-radius:4px}a{color:#3eaf7c}table{border-collapse:collapse;width:100%}th,td{border:1px solid #dfe2e5;padding:.4rem .7rem;text-align:left;font-size:.9rem}</style></head>
<body>
<h1>🗂 Mock LDAP 目录(搜索模拟器)</h1>
<p class="warn"><strong>不是真正的 LDAP 协议服务器。</strong>LDAP 是 TCP(389/636)二进制协议,Cloudflare Workers 无法监听 TCP;这里用 HTTP/JSON 暴露一个固定示例目录并按 RFC 4515 过滤器求值,用于联调搜索/过滤器语义。</p>
<h2>端点</h2>
<table>
<tr><th>整个目录</th><td><a href="${issuer}/ldap/entries"><code>${issuer}/ldap/entries</code></a></td></tr>
<tr><th>搜索</th><td><code>${issuer}/ldap/search?base=&amp;scope=&amp;filter=&amp;attributes=</code></td></tr>
</table>
<h2>示例</h2>
<pre>curl "${issuer}/ldap/search?base=ou=people,dc=example,dc=com&scope=sub&filter=(%26(objectClass=person)(departmentNumber=eng))"</pre>
<p>参数:<code>base</code>(默认 <code>dc=example,dc=com</code>)、<code>scope</code>(<code>base</code>|<code>one</code>|<code>sub</code>,默认 sub)、<code>filter</code>(RFC 4515,默认 <code>(objectClass=*)</code>)、<code>attributes</code>(逗号分隔,选填)。</p>
<p>可视化构建过滤器:见站点的 <a href="https://authn.tech/tools/ldap-filter.html">LDAP 过滤器构建器</a>。</p>
</body></html>`
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } })
}
