import { createHash, webcrypto } from 'node:crypto';

// 11단계: 기기 승인과 요청 서명.
// - 기기 키는 브라우저가 메모리에서만 만든 ECDSA P-256 키입니다. 개인키는 내보낼 수 없게(non-extractable) 만들고
//   브라우저 저장소(localStorage·sessionStorage·IndexedDB·쿠키)에 넣지 않습니다. 서버는 공개키만 받습니다.
// - 기기 ID는 공개키 지문(RFC 7638 SHA-256)의 앞 16자리입니다. 브라우저가 보낸 기기 ID를 그대로 믿지 않습니다.
// - 승인은 화면 버튼이 아니라 서버가 정합니다: 로그인한 본인이 비밀번호를 다시 확인하고(서버가 Supabase에 확인),
//   그 요청이 등록한 기기 키로 서명되어 있을 때만 서버 DB(vault_devices)의 상태를 approved로 바꿉니다.
// - 보호 요청은 승인된 기기 키로 "방식·경로·시각·일회용 값·본문 해시"를 서명해야 합니다.
//   서명 뒤 경로나 본문을 바꾸면 서버가 다시 계산한 값과 달라 403으로 거절합니다.
// 설치형 앱으로 열렸다는 표시(display-mode)나 승인 버튼은 서버 판단에 쓰지 않습니다.

export const SIGNATURE_SCHEME = 'aleph.device.v1';
export const DEVICE_ID = /^[0-9a-f]{16}$/u;
const B64URL_32 = /^[A-Za-z0-9_-]{43}$/u;          // P-256 좌표 32바이트
const B64URL_SIG = /^[A-Za-z0-9_-]{86}$/u;         // P-256 서명 r||s 64바이트
const TIMESTAMP = /^[0-9]{13}$/u;                   // 밀리초 단위 시각
const NONCE = /^[A-Za-z0-9_-]{16,64}$/u;
export const MAX_SKEW_MS = 60 * 1000;               // 서명 시각은 서버 시각 ±60초 안이어야 함
export const DEVICE_HEADERS = Object.freeze({
  device: 'x-aleph-device', timestamp: 'x-aleph-timestamp',
  nonce: 'x-aleph-nonce', signature: 'x-aleph-signature',
});

export const sha256Hex = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

// 브라우저 공개키(JWK)에서 쓸 값만 꺼냅니다. 개인키 값(d)이 섞여 오면 받지 않습니다.
export function publicJwk(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  if ('d' in raw) return null;
  if (raw.kty !== 'EC' || raw.crv !== 'P-256') return null;
  if (typeof raw.x !== 'string' || typeof raw.y !== 'string') return null;
  if (!B64URL_32.test(raw.x) || !B64URL_32.test(raw.y)) return null;
  return { kty: 'EC', crv: 'P-256', x: raw.x, y: raw.y };
}

// RFC 7638 지문(SHA-256)의 앞 16자리 = 기기 ID. 판정기 계약의 deviceId 형식(16자리 소문자 16진수)과 같습니다.
export function deviceIdOf(jwk) {
  const key = publicJwk(jwk);
  if (!key) return null;
  return sha256Hex(`{"crv":"P-256","kty":"EC","x":"${key.x}","y":"${key.y}"}`).slice(0, 16);
}

// 서명할 문장. 브라우저(public/index.html)와 서버가 같은 순서로 만듭니다.
export function canonicalRequest({ method, path, timestamp, nonce, bodySha256 }) {
  return [SIGNATURE_SCHEME, String(method).toUpperCase(), path, timestamp, nonce, bodySha256].join('\n');
}

// 서버가 받은 본문을 다시 글자로 만듭니다. 브라우저는 JSON.stringify(본문)을 그대로 보내고 그 글자를 서명합니다.
export function signedBodyText(req) {
  const body = req.body;
  if (body === undefined || body === null || body === '') return '';
  if (typeof body === 'string') return body;
  if (Buffer.isBuffer(body)) return body.toString('utf8');
  if (typeof body === 'object' && !Array.isArray(body) && Object.keys(body).length === 0
      && !Number(req.headers?.['content-length'])) return '';
  return JSON.stringify(body);
}

export async function verifySignature(jwk, message, signature) {
  const key = publicJwk(jwk);
  if (!key || typeof signature !== 'string' || !B64URL_SIG.test(signature)) return false;
  try {
    const imported = await webcrypto.subtle.importKey('jwk', key,
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return await webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, imported,
      Buffer.from(signature, 'base64url'), Buffer.from(message, 'utf8'));
  } catch {
    return false;
  }
}

function header(req, name) {
  const value = req.headers?.[name];
  return typeof value === 'string' ? value : undefined;
}

const deny = (reason, message, status = 403) => ({ ok: false, status, reason, message });

// 같은 서명을 다시 보내는 재전송을 막는 짧은 기억(서버 인스턴스 안, 서명 유효 시간 동안만).
function replayGuard(now) {
  const seen = new Map();
  return {
    used(key) {
      const t = now();
      for (const [k, at] of seen) if (t - at > MAX_SKEW_MS * 2) seen.delete(k);
      return seen.has(key);
    },
    remember(key) { seen.set(key, now()); },
  };
}

// 요청 서명 확인기.
// mode 'approved' : 승인된 기기만(보호 자료 요청)
// mode 'pending'  : 등록은 됐지만 아직 승인 전인 기기도 허용(승인 요청·상태 확인 전용)
// mode 'register' : 요청 본문에 실린 공개키 자신으로 서명을 확인(처음 등록 전용)
// judgeUnsigned   : 운영 심판 토큰(ES256, 15분, 배포 주소 대상)으로 온 "읽기·검증된 사본 복구"만 서명 없이 허용.
//                   학생 로그인 토큰은 언제나 서명이 필요하고, 심판 토큰이라도 바꾸는 요청(추가·수정·삭제)은 서명이 필요합니다.
export function createDeviceGate({ devices, now = Date.now } = {}) {
  const replay = replayGuard(now);
  return async function checkDevice(req, user, path, { mode = 'approved', judgeUnsigned = false, jwk } = {}) {
    const deviceId = header(req, DEVICE_HEADERS.device);
    const timestamp = header(req, DEVICE_HEADERS.timestamp);
    const nonce = header(req, DEVICE_HEADERS.nonce);
    const signature = header(req, DEVICE_HEADERS.signature);
    const present = [deviceId, timestamp, nonce, signature].filter(v => v !== undefined).length;

    if (present === 0) {
      if (judgeUnsigned && user?.kind === 'judge') return { ok: true, via: 'judge_relay', deviceId: null };
      return deny('device_signature_required', '승인된 기기의 요청 서명이 필요합니다.');
    }
    if (present !== 4 || !DEVICE_ID.test(deviceId) || !TIMESTAMP.test(timestamp)
        || !NONCE.test(nonce) || !B64URL_SIG.test(signature)) {
      return deny('device_signature_malformed', '요청 서명 형식이 맞지 않습니다.');
    }
    if (Math.abs(now() - Number(timestamp)) > MAX_SKEW_MS) {
      return deny('device_signature_expired', '요청 서명 시각이 너무 오래되었습니다.');
    }
    if (replay.used(`${deviceId}:${nonce}`)) {
      return deny('device_signature_replayed', '이미 쓴 요청 서명입니다.');
    }

    let key;
    if (mode === 'register') {
      key = publicJwk(jwk);
      if (!key || deviceIdOf(key) !== deviceId) return deny('device_key_mismatch', '기기 ID와 공개키가 맞지 않습니다.', 400);
    } else {
      const row = devices ? await devices.get(deviceId) : null;
      const owner = row ? String(row.owner_id).toLowerCase() : '';
      if (!row || owner !== String(user?.userId).toLowerCase() || deviceIdOf(row.public_jwk) !== deviceId) {
        return deny('device_not_registered', '등록되지 않은 기기입니다.');
      }
      const allowed = mode === 'pending' ? ['pending', 'approved'] : ['approved'];
      if (!allowed.includes(row.status)) {
        return deny(row.status === 'revoked' ? 'device_revoked' : 'device_not_approved',
          row.status === 'revoked' ? '회수된 기기입니다.' : '아직 승인되지 않은 기기입니다.');
      }
      key = row.public_jwk;
    }

    const message = canonicalRequest({ method: req.method, path, timestamp, nonce,
      bodySha256: sha256Hex(signedBodyText(req)) });
    if (!(await verifySignature(key, message, signature))) {
      return deny('device_signature_invalid', '요청 서명이 맞지 않습니다(경로나 본문이 서명 뒤 바뀌었을 수 있습니다).');
    }
    replay.remember(`${deviceId}:${nonce}`);
    return { ok: true, via: 'device_signature', deviceId };
  };
}

// 서버 DB의 기기 명단(vault_devices). 서버 전용 키로만 읽고 씁니다. 개인키는 받지도 저장하지도 않습니다.
export function supabaseDevices(db) {
  const table = () => db.from('vault_devices');
  return {
    async get(deviceId) {
      const { data, error } = await table().select('device_id, owner_id, public_jwk, status')
        .eq('device_id', deviceId).maybeSingle();
      if (error) throw error;
      return data ?? null;
    },
    async register({ deviceId, ownerId, jwk, now }) {
      const existing = await this.get(deviceId);
      if (existing) {
        return String(existing.owner_id).toLowerCase() === ownerId.toLowerCase() ? existing : 'conflict';
      }
      const { data, error } = await table().insert({ device_id: deviceId, owner_id: ownerId,
        public_jwk: jwk, status: 'pending', created_at: now })
        .select('device_id, owner_id, public_jwk, status').single();
      if (error) {
        if (error.code === '23505') return 'conflict';
        throw error;
      }
      return data;
    },
    async approve({ deviceId, ownerId, now }) {
      const { data, error } = await table().update({ status: 'approved', approved_at: now })
        .eq('device_id', deviceId).eq('owner_id', ownerId).in('status', ['pending', 'approved'])
        .select('device_id, owner_id, public_jwk, status').maybeSingle();
      if (error) throw error;
      return data ?? null;
    },
  };
}
