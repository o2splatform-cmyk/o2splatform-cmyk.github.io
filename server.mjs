#!/usr/bin/env node
/**
 * B2B Citation, Evidence JSON & Workflow Sanitizer MCP / x402 Handler.
 * Zero external dependencies; enforces Base L2 x402 nonce replay bounds (<= 60s),
 * fail-closed bounded nonce cache (MAX_NONCE_CACHE_SIZE = 10,000 without evicting live nonces),
 * strict integer micro-USDC validation, and native secp256k1 ECDSA cryptographic verification
 * binding payerPublicKey -> payerAddress and the full canonical payment payload.
 */
import crypto from 'node:crypto';

const REPLAY_WINDOW_SEC = 60;
const MAX_NONCE_CACHE_SIZE = 10000;
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_HALF_N = SECP256K1_N >> 1n;
const SECP256K1_SPKI_PREFIX_HEX = '3056301006072a8648ce3d020106052b8104000a03420004';
const SEEN_NONCES = new Map();

function pruneExpiredNonces(nowSec) {
  for (const [nonce, ts] of SEEN_NONCES.entries()) {
    if (nowSec - ts > REPLAY_WINDOW_SEC) {
      SEEN_NONCES.delete(nonce);
    }
  }
}

export function resetNonceCacheForTest() {
  SEEN_NONCES.clear();
}

export function buildX402CanonicalMessage({
  chainId,
  assetAddress,
  recipientAddress,
  payerAddress,
  amountMicroUsdc,
  nonce,
  timestampSec,
}) {
  return [
    'x402:eip3009',
    String(chainId),
    String(assetAddress).toLowerCase(),
    String(recipientAddress).toLowerCase(),
    String(payerAddress).toLowerCase(),
    String(amountMicroUsdc),
    String(nonce),
    String(timestampSec),
  ].join(':');
}

export function derivePayerAddressFromSpki(payerPublicKeyHex) {
  if (typeof payerPublicKeyHex !== 'string') {
    return null;
  }
  const cleanHex = payerPublicKeyHex.startsWith('0x')
    ? payerPublicKeyHex.slice(2).toLowerCase()
    : payerPublicKeyHex.toLowerCase();
  if (!/^[0-9a-f]{176}$/.test(cleanHex) || !cleanHex.startsWith(SECP256K1_SPKI_PREFIX_HEX)) {
    return null;
  }
  try {
    const derBuf = Buffer.from(cleanHex, 'hex');
    const pubKeyObj = crypto.createPublicKey({ key: derBuf, format: 'der', type: 'spki' });
    if (pubKeyObj.asymmetricKeyType !== 'ec' || pubKeyObj.asymmetricKeyDetails?.namedCurve !== 'secp256k1') {
      return null;
    }
    const xyBytes = derBuf.subarray(-64);
    const addrHex = crypto.createHash('sha256').update(xyBytes).digest('hex').slice(-40);
    return { address: '0x' + addrHex, pubKeyObj };
  } catch {
    return null;
  }
}

export function createTestPayerIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const payerPublicKey = '0x' + publicKey.export({ format: 'der', type: 'spki' }).toString('hex');
  const derived = derivePayerAddressFromSpki(payerPublicKey);
  return {
    payerAddress: derived.address,
    payerPublicKey,
    privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }),
  };
}

export function signX402PaymentHeader(headerFields, privateKeyPem) {
  const msg = buildX402CanonicalMessage(headerFields);
  const privObj = crypto.createPrivateKey(privateKeyPem);
  const sigBuf = Buffer.from(
    crypto.sign('sha256', Buffer.from(msg, 'utf8'), { key: privObj, dsaEncoding: 'ieee-p1363' })
  );
  const rHex = sigBuf.subarray(0, 32).toString('hex');
  let sBig = BigInt('0x' + sigBuf.subarray(32, 64).toString('hex'));
  if (sBig > SECP256K1_HALF_N) {
    sBig = SECP256K1_N - sBig;
  }
  const sHex = sBig.toString(16).padStart(64, '0');
  return '0x' + rHex + sHex;
}

export function verifyX402PaymentHeader(headerObj, nowSec = Math.floor(Date.now() / 1000)) {
  if (!headerObj || typeof headerObj !== 'object' || Array.isArray(headerObj)) {
    return { ok: false, error: 'Missing or invalid x402 payment header object' };
  }
  if (!Number.isFinite(nowSec) || nowSec <= 0) {
    return { ok: false, error: 'Invalid server evaluation timestamp' };
  }
  const {
    chainId,
    assetAddress,
    recipientAddress,
    payerAddress,
    payerPublicKey,
    amountMicroUsdc,
    nonce,
    timestampSec,
    signature,
  } = headerObj;
  if (chainId !== 8453) {
    return { ok: false, error: 'Unsupported chainId (require Base 8453)' };
  }
  if (typeof assetAddress !== 'string' || assetAddress.toLowerCase() !== '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913') {
    return { ok: false, error: 'Invalid Base USDC asset address' };
  }
  if (typeof recipientAddress !== 'string' || recipientAddress.toLowerCase() !== '0x1111111111111111111111111111111111111111') {
    return { ok: false, error: 'Recipient address mismatch' };
  }
  if (typeof payerAddress !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(payerAddress) || /^0x0{40}$/.test(payerAddress)) {
    return { ok: false, error: 'Invalid or zero payerAddress' };
  }
  const derivedPayer = derivePayerAddressFromSpki(payerPublicKey);
  if (!derivedPayer || derivedPayer.address.toLowerCase() !== payerAddress.toLowerCase()) {
    return { ok: false, error: 'Missing or mismatched secp256k1 payerPublicKey for payerAddress' };
  }
  if (typeof amountMicroUsdc !== 'number' || !Number.isInteger(amountMicroUsdc) || amountMicroUsdc < 50000) {
    return { ok: false, error: 'Insufficient or non-integer payment (require integer >= 50,000 micro-USDC)' };
  }
  if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) {
    return { ok: false, error: 'Invalid payment nonce format (require 16-128 alphanumeric chars)' };
  }
  if (typeof signature !== 'string' || !/^0x[0-9a-fA-F]{128}$/.test(signature)) {
    return { ok: false, error: 'Malformed signature: require exact 64-byte (128 hex chars) IEEE-P1363 secp256k1 signature' };
  }
  const rBig = BigInt('0x' + signature.slice(2, 66));
  const sBig = BigInt('0x' + signature.slice(66, 130));
  if (rBig <= 0n || rBig >= SECP256K1_N || sBig <= 0n || sBig > SECP256K1_HALF_N) {
    return { ok: false, error: 'Invalid or malleable secp256k1 signature scalar (r/s out of low-S bounds)' };
  }
  if (typeof timestampSec !== 'number' || !Number.isInteger(timestampSec) || Math.abs(nowSec - timestampSec) > REPLAY_WINDOW_SEC) {
    return { ok: false, error: 'Payment timestamp outside 60s replay window' };
  }
  const canonicalMsg = buildX402CanonicalMessage({
    chainId,
    assetAddress,
    recipientAddress,
    payerAddress,
    amountMicroUsdc,
    nonce,
    timestampSec,
  });
  const sigVerified = crypto.verify(
    'sha256',
    Buffer.from(canonicalMsg, 'utf8'),
    { key: derivedPayer.pubKeyObj, dsaEncoding: 'ieee-p1363' },
    Buffer.from(signature.slice(2), 'hex')
  );
  if (!sigVerified) {
    return { ok: false, error: 'Cryptographic signature verification failed against canonical x402 payment payload' };
  }
  pruneExpiredNonces(nowSec);
  if (SEEN_NONCES.has(nonce)) {
    return { ok: false, error: 'Replay detected: nonce already consumed within active window' };
  }
  if (SEEN_NONCES.size >= MAX_NONCE_CACHE_SIZE) {
    return { ok: false, error: 'Rate limit exceeded: active nonce window capacity full (fail-closed)' };
  }
  SEEN_NONCES.set(nonce, nowSec);
  return {
    ok: true,
    receiptId: 'x402_' + crypto.createHash('sha256').update(nonce + ':' + signature).digest('hex').slice(0, 24),
  };
}
