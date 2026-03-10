/**
 * Have I Been Pwned API 整合
 * 使用 k-Anonymity：只傳送 SHA-1 前 5 字元，本地比對
 */

const HIBP_RANGE_URL = 'https://api.pwnedpasswords.com/range/';

async function sha1(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * 檢查密碼是否曾遭洩漏
 * @returns { count: number } 洩漏次數，0 表示未洩漏
 */
export async function checkPwned(password) {
  try {
    const fullHash = await sha1(password);
    const prefix = fullHash.substring(0, 5).toUpperCase();
    const suffix = fullHash.substring(5).toUpperCase();
    
    const res = await fetch(`${HIBP_RANGE_URL}${prefix}`, {
      headers: { 'User-Agent': 'Password-Strength-Evaluator/1.0' }
    });
    
    if (!res.ok) throw new Error('API 請求失敗');
    
    const text = await res.text();
    const lines = text.split('\r\n');
    
    for (const line of lines) {
      const [hashSuffix, count] = line.split(':');
      if (hashSuffix.trim() === suffix) {
        return { pwned: true, count: parseInt(count || '0', 10) };
      }
    }
    
    return { pwned: false, count: 0 };
  } catch (err) {
    console.error('HIBP check failed:', err);
    return { pwned: null, count: 0, error: err.message };
  }
}
