// Real-@e2b/sdk driver for tests/10_test_e2b_sdk.sh.
//
// E2B_DEBUG=1 pins the SDK's API host to http://localhost:3000 — the only
// localhost escape hatch the SDK offers — so agentpvm must be listening
// there. These assertions cover what is drivable WITHOUT a UML kernel or a
// guest envd daemon: auth, list shape, and the create/kill error contracts.
// Full-lifecycle compatibility additionally needs an envd-compatible daemon
// inside the guest (see internal/api/e2b_compat.go).

import { Sandbox } from '@e2b/sdk'

const fails = []
function check(name, cond, detail = '') {
  if (cond) console.log(`   ✓ ${name}`)
  else { console.error(`   ❌ ${name}${detail ? ': ' + detail : ''}`); fails.push(name) }
}

async function expectReject(name, promise, substr) {
  try {
    await promise
    check(name, false, 'resolved instead of rejecting')
  } catch (e) {
    const msg = (e && (e.message || String(e))) || ''
    check(name, substr ? msg.includes(substr) : true, `message="${msg}"`)
  }
}

// 1. list() on a fresh state root -> empty array.
const list = await Sandbox.list()
check('list returns empty array', Array.isArray(list) && list.length === 0, JSON.stringify(list))

// 2. wrong API key -> SDK surfaces the server's "unauthenticated" message.
const badKey = 'wrong-key'
await expectReject('wrong key rejected', Sandbox.list(badKey), 'unauthenticated')

// 3. create without templateID -> 400, SDK reports "bad request".
await expectReject(
  'create(empty) reports bad request',
  Sandbox.create(''),
  'bad request'
)

// 4. create with an invalid templateID (path traversal) -> 400 bad request.
await expectReject(
  'create(../etc) reports bad request',
  Sandbox.create('../../etc/passwd'),
  'bad request'
)

// 5. kill unknown sandbox -> rejects (404 from the server).
await expectReject('kill unknown rejects', Sandbox.kill('e2bsdk-ghost000'))

if (fails.length) {
  console.error(`FAILED: ${fails.join(', ')}`)
  process.exit(1)
}
console.log('   all SDK assertions passed')
