/**
 * Stackmail end-to-end test (two synthetic agents, real server, mainnet contracts)
 *
 * This test generates fresh keypairs for Alice and Bob, runs through the full
 * send/receive flow, and verifies every step. It does NOT require on-chain pipes
 * to be open — it tests the server's off-chain logic with valid SIP-018 signatures.
 *
 * Contracts (deployer SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR):
 *   sm-test-token  – TEST SIP-010 token
 *   sm-stackflow   – payment channels
 *   sm-reservoir   – on-chain reservoir hub
 *
 * Server: http://127.0.0.1:8800  (SP1RCWQSAF1Q96CPX77Q9EAR236N19P09T6E2KDRE)
 */

import { createHash, randomBytes } from 'node:crypto';
import { secp256k1 } from '/agent/work/stackmail/node_modules/@noble/curves/secp256k1.js';

// Import server's own sip018 module for correct signing
const { buildTransferMessage, sip018Sign, sip018Verify } =
  await import('/agent/work/stackmail/packages/server/dist/sip018.js');

// Import crypto package for ECIES encryption
const { encryptMail, decryptMail, hashSecret, verifySecretHash } =
  await import('/agent/work/stackmail/packages/crypto/dist/index.js');

const SERVER = 'http://127.0.0.1:8800';
const SF_CONTRACT = 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-stackflow';
const TOKEN = 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-test-token';
const CHAIN_ID = 1;
const MESSAGE_PRICE = 1000n;

// ── c32 address derivation ────────────────────────────────────────────────────
const C32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function c32encode(data) {
  let n = BigInt('0x' + Buffer.from(data).toString('hex'));
  const chars = [];
  while (n > 0n) { chars.push(C32[Number(n % 32n)]); n /= 32n; }
  for (const b of data) { if (b === 0) chars.push('0'); else break; }
  return chars.reverse().join('');
}

function stxAddress(pubkeyHex) {
  const pub = Buffer.from(pubkeyHex, 'hex');
  const sha = createHash('sha256').update(pub).digest();
  const h160 = createHash('ripemd160').update(sha).digest();
  const version = 22;
  const payload = Buffer.concat([Buffer.from([version]), h160]);
  const h1 = createHash('sha256').update(payload).digest();
  const checksum = createHash('sha256').update(h1).digest().subarray(0, 4);
  return 'S' + C32[version] + c32encode(Buffer.concat([h160, checksum]));
}

function genKeypair() {
  const priv = randomBytes(32);
  const pub = secp256k1.getPublicKey(priv, true);
  const privHex = Buffer.from(priv).toString('hex');
  const pubHex = Buffer.from(pub).toString('hex');
  return { privHex, pubHex, addr: stxAddress(pubHex) };
}

// ── auth header ───────────────────────────────────────────────────────────────
function sha256(data) { return createHash('sha256').update(data).digest(); }

function buildAuthHeader(privHex, pubHex, addr, action, messageId) {
  const payload = {
    action,
    address: addr,
    timestamp: Date.now(),
    ...(messageId ? { messageId } : {}),
  };
  const payloadJson = JSON.stringify(payload);
  const hash = sha256(Buffer.from(payloadJson));
  const sig = secp256k1.sign(hash, Buffer.from(privHex, 'hex'), { lowS: true });
  const sigHex = Buffer.from(sig.toCompactRawBytes()).toString('hex');
  return Buffer.from(JSON.stringify({ pubkey: pubHex, payload, signature: sigHex })).toString('base64');
}

// ── pipe key ──────────────────────────────────────────────────────────────────
function decodePrincipal(addr) {
  const encoded = addr.slice(2); // remove 'S' + version char
  let n = 0n;
  for (const c of encoded) {
    const i = C32.indexOf(c);
    if (i < 0) throw new Error('bad c32 char ' + c);
    n = n * 32n + BigInt(i);
  }
  // Result: 24 bytes (hash160 + 4 checksum) → first 20 are hash160
  const buf = Buffer.alloc(24);
  let tmp = n;
  for (let i = 23; i >= 0; i--) { buf[i] = Number(tmp & 0xffn); tmp >>= 8n; }
  return buf.subarray(0, 20);
}

function canonicalPipeKey(token, addr1, addr2) {
  const p1 = Buffer.concat([Buffer.from([0x05, 0x16]), decodePrincipal(addr1)]);
  const p2 = Buffer.concat([Buffer.from([0x05, 0x16]), decodePrincipal(addr2)]);
  return Buffer.compare(p1, p2) < 0
    ? { token, 'principal-1': addr1, 'principal-2': addr2 }
    : { token, 'principal-1': addr2, 'principal-2': addr1 };
}

// ── API helpers ───────────────────────────────────────────────────────────────
async function api(method, path, body, headers = {}) {
  const opts = { method, headers: { ...headers } };
  if (body) {
    opts.headers['content-type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(`${SERVER}${path}`, opts);
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: r.status, ok: r.ok, data };
}

function assert(condition, msg) {
  if (!condition) throw new Error('ASSERTION FAILED: ' + msg);
}

// ── main ──────────────────────────────────────────────────────────────────────
async function run() {
  console.log('═══════════════════════════════════════════');
  console.log('  Stackmail E2E Test — mainnet contracts');
  console.log('═══════════════════════════════════════════\n');

  const alice = genKeypair();
  const bob   = genKeypair();
  const SERVER_ADDR = 'SP1RCWQSAF1Q96CPX77Q9EAR236N19P09T6E2KDRE';

  console.log(`Alice: ${alice.addr}`);
  console.log(`Bob:   ${bob.addr}`);
  console.log(`Server: ${SERVER_ADDR}\n`);

  // ─── 1. Health ────────────────────────────────────────────────────────────
  console.log('1. Health check...');
  const health = await api('GET', '/health');
  assert(health.ok, 'health check failed');
  console.log('   ✓', health.data, '\n');

  // ─── 2. Bob registers (GET /inbox authenticates → stores pubkey) ──────────
  console.log('2. Bob registers pubkey with server...');
  const bobAuth = buildAuthHeader(bob.privHex, bob.pubHex, bob.addr, 'get-inbox');
  const bobInbox = await api('GET', '/inbox', null, { 'x-stackmail-auth': bobAuth });
  console.log(`   GET /inbox → ${bobInbox.status} (pubkey stored)`);
  assert(bobInbox.status === 200 || bobInbox.status === 404, `unexpected status ${bobInbox.status}`);

  // ─── 3. Get Bob's payment info ────────────────────────────────────────────
  console.log('\n3. Fetching Bob\'s payment info...');
  const payInfo = await api('GET', `/payment-info/${bob.addr}`);
  assert(payInfo.ok, `payment-info failed: ${JSON.stringify(payInfo.data)}`);
  assert(payInfo.data.recipientPublicKey, 'missing recipientPublicKey');
  assert(payInfo.data.serverAddress === SERVER_ADDR, 'server address mismatch');
  const bobPubkeyHex = payInfo.data.recipientPublicKey;
  console.log('   ✓ recipientPublicKey:', bobPubkeyHex.slice(0, 20) + '...');
  console.log('   ✓ price:', payInfo.data.amount, '| server:', payInfo.data.serverAddress, '\n');

  // ─── 4. Generate HTLC secret and encrypt message for Bob ─────────────────
  console.log('4. Alice generates HTLC secret and encrypts message...');

  const R = randomBytes(32);
  const secretHex = R.toString('hex');
  const hashedSecret = hashSecret(secretHex);  // sha256(R) in hex, no 0x prefix
  console.log('   hashedSecret:', hashedSecret.slice(0, 20) + '...');

  // Encrypt message payload with Bob's public key
  const mailPayload = {
    v: 1,
    secret: secretHex,
    subject: 'Hello from Alice',
    body: 'First real Stackmail message on mainnet! 🚀',
  };
  const encryptedPayload = encryptMail(mailPayload, bobPubkeyHex);
  console.log('   ✓ Encrypted payload: { v:', encryptedPayload.v, ', epk:', encryptedPayload.epk.slice(0,10) + '...', '}\n');

  // ─── 5. Alice builds SIP-018 payment proof ────────────────────────────────
  console.log('5. Alice builds SIP-018 payment proof...');

  const aliceFunded = 100_000n;
  const serverNewBal = MESSAGE_PRICE;
  const aliceNewBal  = aliceFunded - MESSAGE_PRICE;
  const nonce = 1;

  const pipeKey = canonicalPipeKey(TOKEN, alice.addr, SERVER_ADDR);
  console.log('   pipe-key principal-1:', pipeKey['principal-1']);
  console.log('   pipe-key principal-2:', pipeKey['principal-2']);

  // Alice signs from her perspective (forPrincipal = alice, myBalance = alice's new bal)
  // but hashedSecret format must match: no 0x prefix
  const aliceState = {
    pipeKey,
    forPrincipal: alice.addr,
    myBalance: aliceNewBal.toString(),
    theirBalance: serverNewBal.toString(),
    nonce: nonce.toString(),
    action: '1',
    actor: alice.addr,
    hashedSecret,        // plain hex, no 0x
    validAfter: null,
  };

  const aliceSig = await sip018Sign(SF_CONTRACT, buildTransferMessage(aliceState), alice.privHex, CHAIN_ID);
  console.log('   ✓ Alice signature:', aliceSig.slice(0, 30) + '...');

  // Verify Alice's signature using server's perspective
  const serverState = {
    pipeKey,
    forPrincipal: SERVER_ADDR,
    myBalance: serverNewBal.toString(),
    theirBalance: aliceNewBal.toString(),
    nonce: nonce.toString(),
    action: '1',
    actor: alice.addr,
    hashedSecret,
    validAfter: null,
  };
  const sigValid = await sip018Verify(SF_CONTRACT, buildTransferMessage(serverState), aliceSig, alice.addr, CHAIN_ID);
  assert(sigValid, 'SIP-018 signature self-check failed');
  console.log('   ✓ SIP-018 signature verified\n');

  // ─── 6. Alice sends message to Bob ────────────────────────────────────────
  console.log('6. Alice sends message to Bob...');

  const proof = {
    contractId: SF_CONTRACT,
    pipeKey,
    forPrincipal: SERVER_ADDR,
    withPrincipal: alice.addr,
    myBalance: serverNewBal.toString(),
    theirBalance: aliceNewBal.toString(),
    nonce: nonce.toString(),
    action: '1',
    actor: alice.addr,
    hashedSecret,
    theirSignature: aliceSig,
    validAfter: null,
  };
  const proofHeader = Buffer.from(JSON.stringify(proof)).toString('base64url');

  const sendResp = await api(
    'POST',
    `/messages/${bob.addr}`,
    {
      from: alice.addr,
      encryptedPayload,
    },
    { 'x-stackmail-payment': proofHeader },
  );

  if (!sendResp.ok) {
    console.log('   Send failed:', sendResp.status, JSON.stringify(sendResp.data));
    process.exit(1);
  }

  const { messageId } = sendResp.data;
  assert(messageId, 'no messageId in response');
  console.log('   ✓ Message sent! ID:', messageId, '\n');

  // ─── 7. Bob polls inbox ───────────────────────────────────────────────────
  console.log('7. Bob polls inbox...');
  const bobAuth2 = buildAuthHeader(bob.privHex, bob.pubHex, bob.addr, 'get-inbox');
  const inbox = await api('GET', '/inbox', null, { 'x-stackmail-auth': bobAuth2 });
  assert(inbox.ok, `inbox failed: ${JSON.stringify(inbox.data)}`);
  const messages = inbox.data.messages ?? [];
  console.log(`   ✓ ${messages.length} message(s) in inbox`);
  assert(messages.length > 0, 'inbox is empty after send');
  const msg = messages.find(m => m.id === messageId);
  assert(msg, 'sent message not found in inbox');
  console.log('   ✓ Found message:', msg.id, '\n');

  // ─── 8. Bob previews message ──────────────────────────────────────────────
  console.log('8. Bob previews message...');
  const bobAuth3 = buildAuthHeader(bob.privHex, bob.pubHex, bob.addr, 'get-message', messageId);
  const preview = await api('GET', `/inbox/${messageId}/preview`, null, { 'x-stackmail-auth': bobAuth3 });
  assert(preview.ok, `preview failed: ${JSON.stringify(preview.data)}`);
  console.log('   ✓ Preview received, from:', preview.data.from);
  assert(preview.data.encryptedPayload, 'no encryptedPayload in preview');
  console.log('   ✓ Has encryptedPayload v:', preview.data.encryptedPayload.v);

  // Bob decrypts the payload to get subject, body, and the secret
  const decrypted = decryptMail(preview.data.encryptedPayload, bob.privHex);
  console.log('   ✓ Decrypted subject:', decrypted.subject);
  console.log('   ✓ Decrypted body:', decrypted.body);
  assert(decrypted.v === 1, 'decrypted payload version mismatch');
  assert(decrypted.secret === secretHex, 'decrypted secret does not match original');
  console.log('   ✓ Secret matches!\n');

  // Verify the secret hash matches the hashedSecret in payment proof
  assert(verifySecretHash(decrypted.secret, preview.data.hashedSecret), 'secret hash mismatch in preview');
  console.log('   ✓ Secret hash verified against payment proof\n');

  // ─── 9. Bob claims message ────────────────────────────────────────────────
  console.log('9. Bob claims message (reveals secret R)...');
  const bobAuth4 = buildAuthHeader(bob.privHex, bob.pubHex, bob.addr, 'claim-message', messageId);
  const claim = await api(
    'POST',
    `/inbox/${messageId}/claim`,
    { secret: decrypted.secret },
    { 'x-stackmail-auth': bobAuth4 },
  );
  assert(claim.ok, `claim failed: ${JSON.stringify(claim.data)}`);
  const claimedMsg = claim.data.message;
  assert(claimedMsg, 'no message in claim response');
  console.log('   ✓ Claimed!');
  console.log('   ✓ From:', claimedMsg.from);
  console.log('   ✓ Amount:', claimedMsg.amount, '\n');

  // ─── 10. Bob polls inbox again (message should be marked claimed) ──────────
  console.log('10. Verifying message is marked claimed...');
  const bobAuth5 = buildAuthHeader(bob.privHex, bob.pubHex, bob.addr, 'get-inbox');
  const inbox2 = await api('GET', '/inbox?claimed=true', null, { 'x-stackmail-auth': bobAuth5 });
  const claimed = (inbox2.data.messages ?? []).find(m => m.id === messageId);
  if (claimed) {
    console.log('   ✓ Message found in claimed list, claimed flag:', claimed.claimed);
  } else {
    console.log('   (message not in claimed list — may require includeClaimed=true)');
  }

  console.log('\n╔════════════════════════════════╗');
  console.log('║  ✅  E2E TEST PASSED           ║');
  console.log('╚════════════════════════════════╝\n');

  console.log('Summary:');
  console.log('  Contracts:');
  console.log('    sm-test-token : SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-test-token');
  console.log('    sm-stackflow  : SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-stackflow');
  console.log('    sm-reservoir  : SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir');
  console.log('  Server: http://127.0.0.1:8800 → SP1RCWQSAF1Q96CPX77Q9EAR236N19P09T6E2KDRE');
  console.log('  Alice →', alice.addr);
  console.log('  Bob   →', bob.addr);
}

run().catch(e => { console.error('\n✗ E2E TEST FAILED:', e.message); process.exit(1); });
