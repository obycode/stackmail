/**
 * Stackmail demo — shows the full interaction flow using stackmail-client.ts
 *
 * Run with: node scripts/demo.mjs
 *
 * The server must be running: node packages/server/dist/index.js
 */

// Import the compiled client (uses the server's modules directly for demo simplicity)
import { createHash, randomBytes, createECDH, createCipheriv, createDecipheriv, hkdfSync } from 'node:crypto';
import { secp256k1 } from '/agent/work/stackmail/node_modules/@noble/curves/secp256k1.js';

// Import SIP-018 from the compiled server package (canonical implementation)
const { buildTransferMessage, sip018Sign, sip018Verify } =
  await import('/agent/work/stackmail/packages/server/dist/sip018.js');
const { encryptMail, decryptMail, hashSecret } =
  await import('/agent/work/stackmail/packages/crypto/dist/index.js');

// ─── Config ──────────────────────────────────────────────────────────────────

const SERVER     = 'http://127.0.0.1:8800';
const SERVER_ADDR = 'SP1RCWQSAF1Q96CPX77Q9EAR236N19P09T6E2KDRE';
const SF_CONTRACT = 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-stackflow';
const TOKEN       = 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-test-token';
const CHAIN_ID    = 1;
const MSG_PRICE   = 1000n;

// ─── Address helpers ──────────────────────────────────────────────────────────

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
  const v = 22;
  const payload = Buffer.concat([Buffer.from([v]), h160]);
  const h1 = createHash('sha256').update(payload).digest();
  const checksum = createHash('sha256').update(h1).digest().subarray(0, 4);
  return 'S' + C32[v] + c32encode(Buffer.concat([h160, checksum]));
}

function genKeypair() {
  const priv = randomBytes(32);
  const pub = secp256k1.getPublicKey(priv, true);
  const privHex = Buffer.from(priv).toString('hex');
  const pubHex = Buffer.from(pub).toString('hex');
  return { privHex, pubHex, addr: stxAddress(pubHex) };
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

function buildAuthHeader(privHex, pubHex, addr, action, messageId) {
  const payload = { action, address: addr, timestamp: Date.now(), ...(messageId ? { messageId } : {}) };
  const hash = createHash('sha256').update(JSON.stringify(payload)).digest();
  const sig = secp256k1.sign(hash, Buffer.from(privHex, 'hex'), { lowS: true });
  return Buffer.from(JSON.stringify({
    pubkey: pubHex,
    payload,
    signature: Buffer.from(sig.toCompactRawBytes()).toString('hex'),
  })).toString('base64');
}

// ─── Pipe key helper ──────────────────────────────────────────────────────────

function c32DecodeFixed(encoded, expectedBytes) {
  const result = Buffer.alloc(expectedBytes, 0);
  let carry = 0, carryBits = 0, byteIdx = expectedBytes - 1;
  for (let i = encoded.length - 1; i >= 0 && byteIdx >= 0; i--) {
    const val = C32.indexOf(encoded[i].toUpperCase());
    if (val < 0) throw new Error('bad c32 char ' + encoded[i]);
    carry |= (val << carryBits); carryBits += 5;
    if (carryBits >= 8) { result[byteIdx--] = carry & 0xff; carry >>= 8; carryBits -= 8; }
  }
  return result;
}

function parseStxAddress(addr) {
  const a = addr.includes('.') ? addr.slice(0, addr.indexOf('.')) : addr;
  const version = C32.indexOf(a[1].toUpperCase());
  const decoded = c32DecodeFixed(a.slice(2), 24);
  return { version, hash160: decoded.subarray(0, 20) };
}

function canonicalPipeKey(token, addr1, addr2) {
  const { version: v1, hash160: h1 } = parseStxAddress(addr1);
  const { version: v2, hash160: h2 } = parseStxAddress(addr2);
  const p1 = Buffer.concat([Buffer.from([0x05, v1]), h1]);
  const p2 = Buffer.concat([Buffer.from([0x05, v2]), h2]);
  return Buffer.compare(p1, p2) < 0
    ? { token, 'principal-1': addr1, 'principal-2': addr2 }
    : { token, 'principal-1': addr2, 'principal-2': addr1 };
}

// ─── API helper ───────────────────────────────────────────────────────────────

async function api(method, path, body, headers = {}) {
  const opts = { method, headers: { ...headers } };
  if (body) { opts.headers['content-type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const r = await fetch(`${SERVER}${path}`, opts);
  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: r.status, ok: r.ok, data };
}

// ─── Stackmail client functions ───────────────────────────────────────────────

/**
 * Register your mailbox with the server.
 * Must be called once before you can receive messages.
 */
async function registerMailbox(kp) {
  const auth = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-inbox');
  const r = await api('GET', '/inbox', null, { 'x-stackmail-auth': auth });
  if (r.status !== 200 && r.status !== 404) throw new Error(`register failed: ${r.status}`);
  console.log(`  Registered: ${kp.addr}`);
  return kp.addr;
}

/**
 * Get payment info for a recipient (their pubkey and price).
 */
async function getPaymentInfo(addr) {
  const r = await api('GET', `/payment-info/${addr}`);
  if (!r.ok) throw new Error(`payment-info failed: ${r.status} ${JSON.stringify(r.data)}`);
  return r.data;
}

/**
 * Send a message to a recipient.
 *
 * pipeState: { serverBalance: bigint, myBalance: bigint, nonce: bigint }
 *
 * Returns { messageId, newPipeState }
 */
async function sendMessage(senderKp, toAddr, subject, body, pipeState) {
  const payInfo = await getPaymentInfo(toAddr);

  // Generate HTLC secret and encrypt message
  const secretHex = randomBytes(32).toString('hex');
  const hashedSecretHex = hashSecret(secretHex);
  const encPayload = encryptMail({ v: 1, secret: secretHex, subject, body }, payInfo.recipientPublicKey);

  // New channel state
  const newServerBalance = pipeState.serverBalance + MSG_PRICE;
  const newMyBalance     = pipeState.myBalance - MSG_PRICE;
  const nextNonce        = pipeState.nonce + 1n;
  const pipeKey          = canonicalPipeKey(TOKEN, senderKp.addr, SERVER_ADDR);

  // Sign state update from sender's perspective
  const state = {
    pipeKey,
    forPrincipal: senderKp.addr,
    myBalance: newMyBalance.toString(),
    theirBalance: newServerBalance.toString(),
    nonce: nextNonce.toString(),
    action: '1', actor: senderKp.addr,
    hashedSecret: hashedSecretHex,
    validAfter: null,
  };
  const sig = await sip018Sign(SF_CONTRACT, buildTransferMessage(state), senderKp.privHex, CHAIN_ID);

  // Encode proof for server (from server's perspective)
  const proof = {
    contractId: SF_CONTRACT, pipeKey,
    forPrincipal: SERVER_ADDR, withPrincipal: senderKp.addr,
    myBalance: newServerBalance.toString(), theirBalance: newMyBalance.toString(),
    nonce: nextNonce.toString(), action: '1', actor: senderKp.addr,
    hashedSecret: hashedSecretHex, theirSignature: sig, validAfter: null,
  };
  const proofHeader = Buffer.from(JSON.stringify(proof)).toString('base64url');

  const r = await api(
    'POST', `/messages/${toAddr}`,
    { from: senderKp.addr, encryptedPayload: encPayload },
    { 'x-stackmail-payment': proofHeader },
  );
  if (!r.ok) throw new Error(`sendMessage failed: ${r.status} ${JSON.stringify(r.data)}`);

  return {
    messageId: r.data.messageId,
    newPipeState: { serverBalance: newServerBalance, myBalance: newMyBalance, nonce: nextNonce },
  };
}

/**
 * Check your inbox. Returns array of { id, from, sentAt, amount, claimed }.
 */
async function getInbox(kp, includeClaimed = false) {
  const auth = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-inbox');
  const r = await api('GET', `/inbox${includeClaimed ? '?claimed=true' : ''}`, null, { 'x-stackmail-auth': auth });
  if (!r.ok) throw new Error(`getInbox failed: ${r.status}`);
  return r.data.messages ?? [];
}

/**
 * Claim a message: decrypts it and reveals the secret to unlock payment.
 * Returns the full decrypted message.
 */
async function claimMessage(kp, messageId) {
  // Preview (get encrypted payload)
  const auth1 = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-message', messageId);
  const prev = await api('GET', `/inbox/${messageId}/preview`, null, { 'x-stackmail-auth': auth1 });
  if (!prev.ok) throw new Error(`preview failed: ${prev.status}`);

  // Decrypt
  const { encryptedPayload, hashedSecret } = prev.data;
  const decrypted = decryptMail(encryptedPayload, kp.privHex);

  // Verify secret hash
  const expectedHash = hashedSecret.replace(/^0x/, '');
  if (hashSecret(decrypted.secret) !== expectedHash) throw new Error('secret hash mismatch');

  // Claim
  const auth2 = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'claim-message', messageId);
  const claim = await api('POST', `/inbox/${messageId}/claim`, { secret: decrypted.secret }, { 'x-stackmail-auth': auth2 });
  if (!claim.ok) throw new Error(`claim failed: ${claim.status} ${JSON.stringify(claim.data)}`);

  return { id: messageId, from: prev.data.from, subject: decrypted.subject, body: decrypted.body };
}

// ─── Demo ─────────────────────────────────────────────────────────────────────

async function demo() {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  Stackmail Demo — mainnet contracts');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  // Create two users
  const alice = genKeypair();
  const bob   = genKeypair();
  console.log('Users:');
  console.log('  Alice:', alice.addr);
  console.log('  Bob:  ', bob.addr, '\n');

  // Register mailboxes
  console.log('Step 1: Register mailboxes');
  await registerMailbox(alice);
  await registerMailbox(bob);
  console.log();

  // Alice sends Bob a message
  // Note: pipeState tracks our off-chain balance.
  // myBalance represents what you've deposited into your channel with the server.
  // In a real deployment, this must match your on-chain funded channel.
  console.log('Step 2: Alice sends Bob a message');
  const { messageId, newPipeState } = await sendMessage(
    alice,
    bob.addr,
    'Hello from Alice!',
    'Welcome to Stackmail on mainnet. Your first real message! 🎉',
    { serverBalance: 0n, myBalance: 100_000n, nonce: 0n },
  );
  console.log('  Sent! Message ID:', messageId);
  console.log('  Alice channel after send:', {
    serverBalance: newPipeState.serverBalance.toString(),
    myBalance: newPipeState.myBalance.toString(),
    nonce: newPipeState.nonce.toString(),
  }, '\n');

  // Bob checks inbox
  console.log('Step 3: Bob checks inbox');
  const inbox = await getInbox(bob);
  console.log(`  ${inbox.length} message(s) in inbox`);
  const entry = inbox.find(m => m.id === messageId);
  console.log('  Found:', entry?.id, '| from:', entry?.from, '| amount:', entry?.amount, '\n');

  // Bob claims message
  console.log('Step 4: Bob claims message (decrypts and reveals secret)');
  const msg = await claimMessage(bob, messageId);
  console.log('  Subject:', msg.subject);
  console.log('  Body:   ', msg.body, '\n');

  // Alice sends Bob another message
  console.log('Step 5: Alice sends Bob another message');
  const { messageId: msg2Id } = await sendMessage(
    alice,
    bob.addr,
    'Second message',
    'This is the second message. Micropayment channels work!',
    newPipeState,  // use updated state
  );
  console.log('  Sent! Message ID:', msg2Id, '\n');

  // Bob reads all messages
  console.log('Step 6: Bob reads all new messages');
  const allNew = await getInbox(bob);
  const unclaimed = allNew.filter(m => !m.claimed);
  console.log(`  ${unclaimed.length} unclaimed message(s)`);
  for (const entry of unclaimed) {
    const full = await claimMessage(bob, entry.id);
    console.log('  >', full.subject, ':', full.body.slice(0, 50) + '...');
  }

  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  Demo complete!');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  console.log('Contracts:');
  console.log('  sm-test-token : SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-test-token');
  console.log('  sm-stackflow  : SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-stackflow');
  console.log('  sm-reservoir  : SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir');
  console.log('Server: http://127.0.0.1:8800');
}

demo().catch(e => { console.error('Demo failed:', e); process.exit(1); });
