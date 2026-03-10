/**
 * 密碼強度分析器
 * 數學模型：資訊熵 + 馬可夫鏈 + 模式偵測（社交工程誘餌）
 */

// 常見鍵盤序列與可預測模式（駭客常見破解路徑）
const KEYBOARD_PATTERNS = [
  'qwerty', 'asdf', 'zxcv', '123456', 'qazwsx', '1qaz2wsx',
  'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'password', 'admin',
  'letmein', 'monkey', 'dragon', 'master', 'sunshine', 'princess',
  'iloveyou', 'welcome', 'trustno1', 'abc123', 'qwerty123',
  'password1', 'admin123', '12345678', '123456789', '1234567890'
];

// 常見字元替換規律（看起來強但可預測）
const COMMON_SUBSTITUTIONS = {
  'a': ['@', '4'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'],
  's': ['$', '5'], 't': ['7'], 'b': ['8'], 'g': ['9']
};

// 鍵盤相鄰字元（簡化版）
const ADJACENT_KEYS = {
  'q': 'wa12', 'w': 'qeas23', 'e': 'wrds34', 'r': 'etdf45', 't': 'ryfg56',
  'y': 'tugh67', 'u': 'yihj78', 'i': 'uokj89', 'o': 'iplk90', 'p': 'o0l',
  'a': 'qwsz', 's': 'awedxz', 'd': 'serfcx', 'f': 'drtgvc', 'g': 'ftyhbv',
  'h': 'gyujnb', 'j': 'huikmn', 'k': 'jiolm', 'l': 'kop',
  'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn',
  'n': 'bhjm', 'm': 'njk', '1': '2q', '2': '13qw', '3': '24we', '4': '35er',
  '5': '46rt', '6': '57ty', '7': '68yu', '8': '79ui', '9': '80io', '0': '9op'
};

/**
 * 計算資訊熵 H(X) = -Σ P(x_i) log2(P(x_i))
 * 使用字元出現頻率估算
 */
function calculateEntropy(password) {
  if (!password || password.length === 0) return 0;
  
  const freq = {};
  for (const c of password) {
    freq[c] = (freq[c] || 0) + 1;
  }
  
  const len = password.length;
  let entropy = 0;
  
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  
  // 乘以長度得到總熵（每個位置獨立估算）
  return Math.round(entropy * len * 10) / 10;
}

/**
 * 馬可夫鏈調整：檢測可預測的字符轉換，降低「看起來強但符合規律」的分數
 * 使用相鄰鍵盤與常見序列的機率懲罰
 */
function markovPenalty(password) {
  if (!password || password.length < 2) return 1;
  
  const lower = password.toLowerCase();
  let penalty = 0;
  
  for (let i = 0; i < lower.length - 1; i++) {
    const curr = lower[i];
    const next = lower[i + 1];
    
    if (ADJACENT_KEYS[curr] && ADJACENT_KEYS[curr].includes(next)) {
      penalty += 0.15; // 相鄰鍵盤
    }
    
    if (curr === next) {
      penalty += 0.1; // 重複字元
    }
    
    const codeCurr = curr.charCodeAt(0);
    const codeNext = next.charCodeAt(0);
    if (Math.abs(codeNext - codeCurr) === 1 && (
      (codeCurr >= 97 && codeCurr <= 122) || // a-z
      (codeCurr >= 48 && codeCurr <= 57)     // 0-9
    )) {
      penalty += 0.12; // 順序字母/數字
    }
  }
  
  return Math.max(0.3, 1 - penalty);
}

/**
 * 社交工程誘餌：檢測常見替換規律（P@ssw0rd 類型）
 */
function detectSubstitutionPattern(password) {
  const lower = password.toLowerCase();
  let score = 1;
  
  for (const [char, subs] of Object.entries(COMMON_SUBSTITUTIONS)) {
    for (const sub of subs) {
      if (lower.includes(sub) || password.includes(sub)) {
        const replaced = lower.replace(new RegExp(sub, 'gi'), char);
        if (KEYBOARD_PATTERNS.some(p => replaced.includes(p) || p.includes(replaced))) {
          score *= 0.7;
        }
      }
    }
  }
  
  // 檢查是否為常見密碼 + 替換
  const normalized = lower.replace(/[0@4]/g, 'a').replace(/[3]/g, 'e')
    .replace(/[1!]/g, 'i').replace(/[0]/g, 'o').replace(/[$5]/g, 's');
  
  for (const pattern of KEYBOARD_PATTERNS) {
    if (normalized.includes(pattern) || pattern.includes(normalized)) {
      score *= 0.5;
    }
  }
  
  return Math.max(0.2, score);
}

/**
 * 檢查是否包含鍵盤序列
 */
function containsKeyboardPattern(password) {
  const lower = password.toLowerCase();
  for (const pattern of KEYBOARD_PATTERNS) {
    if (pattern.length >= 4 && lower.includes(pattern)) {
      return pattern;
    }
  }
  return null;
}

/**
 * 綜合強度評估
 */
export function analyzePassword(password) {
  const entropy = calculateEntropy(password);
  const markov = markovPenalty(password);
  const substitution = detectSubstitutionPattern(password);
  const keyboardPattern = containsKeyboardPattern(password);
  
  // 綜合分數 = 熵 * 馬可夫調整 * 替換調整
  const rawScore = entropy * markov * substitution;
  
  let strength, strengthPercent;
  if (rawScore < 20) {
    strength = '弱';
    strengthPercent = Math.min(25, rawScore);
  } else if (rawScore < 35) {
    strength = '中等';
    strengthPercent = 25 + (rawScore - 20);
  } else if (rawScore < 50) {
    strength = '良好';
    strengthPercent = 40 + (rawScore - 35);
  } else {
    strength = '強';
    strengthPercent = Math.min(100, 55 + (rawScore - 50));
  }
  
  const warnings = [];
  if (password.length < 8) warnings.push('長度過短，建議至少 12 字元');
  if (keyboardPattern) warnings.push(`偵測到鍵盤序列「${keyboardPattern}」`);
  if (markov < 0.7) warnings.push('含有相鄰鍵盤或連續字元，易被猜到');
  if (substitution < 0.6) warnings.push('符合常見替換規律（如 P@ssw0rd），建議更隨機');
  if (entropy < 3 * password.length) warnings.push('字元重複度高，熵值偏低');
  
  const recommendations = [];
  if (password.length < 12) recommendations.push('增加長度至 12+ 字元');
  if (!/[A-Z]/.test(password)) recommendations.push('加入大寫字母');
  if (!/[a-z]/.test(password)) recommendations.push('加入小寫字母');
  if (!/[0-9]/.test(password)) recommendations.push('加入數字');
  if (!/[^A-Za-z0-9]/.test(password)) recommendations.push('加入特殊符號');
  if (keyboardPattern || markov < 0.8) recommendations.push('避免鍵盤序列，使用隨機組合');
  
  return {
    entropy,
    markovScore: Math.round(markov * 100),
    substitutionScore: Math.round(substitution * 100),
    rawScore,
    strength,
    strengthPercent: Math.min(100, Math.max(0, Math.round(strengthPercent))),
    warnings,
    recommendations
  };
}
