/**
 * 密碼強度動態評估與管理系統
 * 資訊熵 × 馬可夫鏈 × Have I Been Pwned × Web Crypto × Firebase Auth
 */

import { auth, signIn, signUp, logout, onAuth } from './firebase.js';
import { analyzePassword } from './passwordAnalyzer.js';
import { checkPwned } from './hibp.js';
import { initVault, unlockVault, saveVault, hasVault } from './vault.js';

const authScreen = document.getElementById('authScreen');
const mainApp = document.getElementById('mainApp');
const authForm = document.getElementById('authForm');
const authEmail = document.getElementById('authEmail');
const authPassword = document.getElementById('authPassword');
const authError = document.getElementById('authError');
const authSubmit = document.getElementById('authSubmit');
const authTabs = document.querySelectorAll('.auth-tab');
const logoutBtn = document.getElementById('logoutBtn');

const passwordInput = document.getElementById('passwordInput');
const toggleVisibility = document.getElementById('toggleVisibility');
const strengthMeter = document.querySelector('.strength-meter .meter-bar');
const meterLabel = document.querySelector('.meter-label');
const entropyEl = document.getElementById('entropy');
const markovEl = document.getElementById('markovScore');
const pwnedEl = document.getElementById('pwnedStatus');
const warningsEl = document.getElementById('warnings');
const recommendationsEl = document.getElementById('recommendations');

const masterPassword = document.getElementById('masterPassword');
const unlockBtn = document.getElementById('unlockVault');
const vaultStatus = document.getElementById('vaultStatus');
const vaultEntries = document.getElementById('vaultEntries');
const newSite = document.getElementById('newSite');
const newPassword = document.getElementById('newPassword');
const addEntryBtn = document.getElementById('addEntry');

let pwnedCheckTimeout = null;
let vaultState = null;
let isRegisterMode = false;

function lockVaultUI(message = '請輸入主密碼並點「解鎖 / 初始化」') {
  vaultState = null;
  masterPassword.value = '';
  newSite.value = '';
  newPassword.value = '';
  vaultEntries.innerHTML = '';
  vaultStatus.textContent = message;
}

function clearAnalyzerUI() {
  passwordInput.type = 'password';
  toggleVisibility.textContent = '👁';
  passwordInput.value = '';
  runAnalysis();
}

// --- Firebase 認證流程 ---
onAuth((user) => {
  if (user) {
    authScreen.hidden = true;
    mainApp.hidden = false;
    lockVaultUI();
    clearAnalyzerUI();
  } else {
    authScreen.hidden = false;
    mainApp.hidden = true;
    lockVaultUI('');
    initAuthScreen();
    clearAnalyzerUI();
  }
});

function initAuthScreen() {
  authForm.reset();
  authError.textContent = '';
  authTabs.forEach(tab => {
    tab.classList.toggle('active', tab.dataset.tab === 'login');
  });
  authSubmit.textContent = '登入';
  isRegisterMode = false;
}

authTabs.forEach(tab => {
  tab.addEventListener('click', () => {
    isRegisterMode = tab.dataset.tab === 'register';
    authTabs.forEach(t => t.classList.toggle('active', t === tab));
    authSubmit.textContent = isRegisterMode ? '註冊' : '登入';
    authError.textContent = '';
  });
});

authForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  authError.textContent = '';
  const email = authEmail.value.trim();
  const password = authPassword.value;
  if (!email || !password) {
    authError.textContent = '請填寫信箱與密碼';
    return;
  }
  const origText = authSubmit.textContent;
  authSubmit.disabled = true;
  authSubmit.textContent = isRegisterMode ? '註冊中…' : '登入中…';
  try {
    if (isRegisterMode) {
      await signUp(email, password);
    } else {
      await signIn(email, password);
    }
  } catch (err) {
    console.error('Auth error:', err);
    const msg = err.code === 'auth/email-already-in-use' ? '此信箱已註冊'
      : err.code === 'auth/invalid-email' ? '信箱格式不正確'
      : err.code === 'auth/weak-password' ? '密碼至少需 6 字元'
      : err.code === 'auth/invalid-credential' ? '信箱或密碼錯誤'
      : err.code === 'auth/user-not-found' ? '信箱或密碼錯誤'
      : err.code === 'auth/wrong-password' ? '密碼錯誤'
      : err.message || '發生錯誤，請檢查網路連線';
    authError.textContent = msg;
  } finally {
    authSubmit.disabled = false;
    authSubmit.textContent = origText;
  }
});

logoutBtn.addEventListener('click', () => logout());

// --- 密碼評估 ---
function updateStrengthUI(analysis, pwned = null) {
  strengthMeter.style.width = analysis.strengthPercent + '%';
  strengthMeter.className = 'meter-bar ' + 
    (analysis.strengthPercent < 30 ? 'weak' : 
     analysis.strengthPercent < 50 ? 'fair' : 
     analysis.strengthPercent < 75 ? 'good' : 'strong');
  meterLabel.textContent = `強度：${analysis.strength}`;
  
  entropyEl.textContent = analysis.entropy + ' bits';
  markovEl.textContent = analysis.markovScore + '%';
  
  if (pwned === null) {
    pwnedEl.textContent = '檢查中…';
    pwnedEl.className = 'metric-value';
  } else if (pwned.pwned) {
    pwnedEl.textContent = `⚠ 已洩漏 ${pwned.count} 次`;
    pwnedEl.className = 'metric-value pwned';
  } else if (pwned.error) {
    pwnedEl.textContent = '連線失敗';
    pwnedEl.className = 'metric-value';
  } else {
    pwnedEl.textContent = '✓ 未洩漏';
    pwnedEl.className = 'metric-value safe';
  }
  
  warningsEl.innerHTML = analysis.warnings
    .map(w => `<div class="warning-item">${w}</div>`).join('');
  recommendationsEl.innerHTML = analysis.recommendations
    .map(r => `<div class="rec-item">${r}</div>`).join('');
}

/** 將全形數字等正規化為半形，避免 IME 或數字鍵盤輸入沒觸發 input */
function normalizePassword(str) {
  return str.replace(/[\uff10-\uff19]/g, c =>
    String.fromCharCode(c.charCodeAt(0) - 0xfee0)
  );
}

async function runAnalysis() {
  const raw = passwordInput.value;
  const pwd = normalizePassword(raw);

  if (!pwd) {
    strengthMeter.style.width = '0';
    meterLabel.textContent = '強度：—';
    entropyEl.textContent = '— bits';
    markovEl.textContent = '—';
    pwnedEl.textContent = '—';
    pwnedEl.className = 'metric-value';
    warningsEl.innerHTML = '';
    recommendationsEl.innerHTML = '';
    return;
  }

  let analysis;
  try {
    analysis = analyzePassword(pwd);
  } catch (err) {
    console.error('分析錯誤:', err);
    return;
  }
  updateStrengthUI(analysis, null);

  if (pwnedCheckTimeout) clearTimeout(pwnedCheckTimeout);
  pwnedCheckTimeout = setTimeout(async () => {
    const pwned = await checkPwned(pwd);
    updateStrengthUI(analysis, pwned);
  }, 500);
}

passwordInput.addEventListener('input', runAnalysis);
passwordInput.addEventListener('keyup', runAnalysis);
passwordInput.addEventListener('paste', () => setTimeout(runAnalysis, 50));

toggleVisibility.addEventListener('click', () => {
  const isPass = passwordInput.type === 'password';
  passwordInput.type = isPass ? 'text' : 'password';
  toggleVisibility.textContent = isPass ? '🙈' : '👁';
});

// --- 密碼庫 ---
function renderVaultEntries(entries) {
  vaultEntries.innerHTML = entries.map((e, i) => `
    <div class="vault-entry">
      <span class="site">${escapeHtml(e.site)}</span>
      <span class="password-masked">${'•'.repeat(Math.min(12, e.password?.length || 0))}</span>
      <button class="copy-btn" data-idx="${i}">複製</button>
      <button class="del-btn" data-idx="${i}">刪除</button>
    </div>
  `).join('');
  
  vaultEntries.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.idx, 10);
      navigator.clipboard.writeText(entries[idx].password);
      btn.textContent = '已複製';
      setTimeout(() => btn.textContent = '複製', 1500);
    });
  });
  
  vaultEntries.querySelectorAll('.del-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const idx = parseInt(btn.dataset.idx, 10);
      vaultState.entries.splice(idx, 1);
      await saveVault(vaultState.entries, vaultState.key, vaultState.uid);
      renderVaultEntries(vaultState.entries);
    });
  });
}

function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

unlockBtn.addEventListener('click', async () => {
  const user = auth.currentUser;
  if (!user) {
    vaultStatus.textContent = '請先登入';
    return;
  }

  const pw = masterPassword.value;
  if (!pw) {
    vaultStatus.textContent = '請輸入主密碼';
    return;
  }

  const uid = user.uid;

  if (!hasVault(uid)) {
    await initVault(pw, uid);
    vaultState = await unlockVault(pw, uid);
    if (vaultState) {
      vaultStatus.textContent = '已初始化密碼庫';
      renderVaultEntries(vaultState.entries);
    } else {
      vaultStatus.textContent = '初始化失敗';
    }
  } else {
    vaultState = await unlockVault(pw, uid);
    if (vaultState) {
      vaultStatus.textContent = '已解鎖';
      renderVaultEntries(vaultState.entries);
    } else {
      vaultStatus.textContent = '主密碼錯誤';
    }
  }
});

addEntryBtn.addEventListener('click', async () => {
  if (!vaultState) {
    vaultStatus.textContent = '請先解鎖密碼庫';
    return;
  }
  
  const site = newSite.value.trim();
  const password = newPassword.value;
  
  if (!site || !password) {
    vaultStatus.textContent = '請填寫網站與密碼';
    return;
  }
  
  vaultState.entries.push({ site, password });
  await saveVault(vaultState.entries, vaultState.key, vaultState.uid);
  renderVaultEntries(vaultState.entries);
  newSite.value = '';
  newPassword.value = '';
  vaultStatus.textContent = '已新增';
});
