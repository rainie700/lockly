/**
 * 密碼庫 - Web Crypto API 加解密
 * 資料僅儲存於 localStorage，以主密碼衍生的金鑰加密
 * 並依 Firebase 使用者 UID 做資料隔離（同一台電腦多帳號不互通）
 */

const LEGACY_STORAGE_KEY = 'pwd_vault_enc';
const LEGACY_SALT_KEY = 'pwd_vault_salt';

function getKeys(uid) {
  if (!uid) throw new Error('uid is required');
  return {
    storageKey: `pwd_vault_enc_${uid}`,
    saltKey: `pwd_vault_salt_${uid}`,
    legacyStorageKey: LEGACY_STORAGE_KEY,
    legacySaltKey: LEGACY_SALT_KEY
  };
}

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );
  
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}

export async function initVault(masterPassword, uid) {
  const { storageKey, saltKey } = getKeys(uid);
  const salt = generateSalt();
  const key = await deriveKey(masterPassword, salt);
  const entries = [];
  const plain = JSON.stringify({ ownerUid: uid, entries });
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    key,
    enc.encode(plain)
  );
  const combined = new Uint8Array(iv.length + cipher.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(cipher), iv.length);
  localStorage.setItem(storageKey, btoa(String.fromCharCode(...combined)));
  localStorage.setItem(saltKey, btoa(String.fromCharCode(...salt)));
  return true;
}

async function decrypt(ciphertext, key) {
  const raw = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
  const iv = raw.slice(0, 12);
  const data = raw.slice(12);
  
  const dec = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    key,
    data
  );
  return new TextDecoder().decode(dec);
}

function getStoredVaultBlob({ storageKey, saltKey, legacyStorageKey, legacySaltKey }) {
  const encrypted = localStorage.getItem(storageKey);
  const saltB64 = localStorage.getItem(saltKey);
  if (encrypted && saltB64) return { encrypted, saltB64, isLegacy: false };

  const legacyEncrypted = localStorage.getItem(legacyStorageKey);
  const legacySaltB64 = localStorage.getItem(legacySaltKey);
  if (legacyEncrypted && legacySaltB64) return { encrypted: legacyEncrypted, saltB64: legacySaltB64, isLegacy: true };

  return null;
}

export async function unlockVault(masterPassword, uid) {
  const keys = getKeys(uid);
  const stored = getStoredVaultBlob(keys);
  if (!stored) return null;

  const salt = Uint8Array.from(atob(stored.saltB64), c => c.charCodeAt(0));
  const key = await deriveKey(masterPassword, salt);

  try {
    const plain = await decrypt(stored.encrypted, key);
    const parsed = JSON.parse(plain);
    const entries = Array.isArray(parsed) ? parsed : (parsed?.entries ?? []);

    if (!Array.isArray(parsed) && parsed?.ownerUid && parsed.ownerUid !== uid) {
      return null;
    }

    // 若是舊版（未分帳號）資料，成功解鎖後立刻遷移到此 UID 並刪除舊資料，避免跨帳號看到同一份。
    if (stored.isLegacy) {
      localStorage.setItem(keys.saltKey, stored.saltB64);
      // 重新加密並寫入 UID 專屬的 vault（同時把 ownerUid 寫進去）
      await saveVault(entries, key, uid);
      localStorage.removeItem(keys.legacyStorageKey);
      localStorage.removeItem(keys.legacySaltKey);
    }

    return { entries, key, uid };
  } catch (e) {
    return null;
  }
}

export async function saveVault(entries, key, uid) {
  const { storageKey } = getKeys(uid);
  const plain = JSON.stringify({ ownerUid: uid, entries });
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    key,
    enc.encode(plain)
  );
  const combined = new Uint8Array(iv.length + cipher.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(cipher), iv.length);
  localStorage.setItem(storageKey, btoa(String.fromCharCode(...combined)));
}

export function hasVault(uid) {
  const { storageKey, legacyStorageKey } = getKeys(uid);
  return !!localStorage.getItem(storageKey) || !!localStorage.getItem(legacyStorageKey);
}
