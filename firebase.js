/**
 * Firebase 初始化與 Authentication
 */
import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js';
import {
  getAuth,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
  onAuthStateChanged
} from 'https://www.gstatic.com/firebasejs/10.14.1/firebase-auth.js';

const firebaseConfig = {
  apiKey: 'AIzaSyCZF0QfO5Llx3kEX-RXMzQ7HCGdpOstE88',
  authDomain: 'lockly-7c888.firebaseapp.com',
  projectId: 'lockly-7c888',
  storageBucket: 'lockly-7c888.firebasestorage.app',
  messagingSenderId: '472397781689',
  appId: '1:472397781689:web:c79296406bea521e4ed968'
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);

export async function signUp(email, password) {
  return createUserWithEmailAndPassword(auth, email, password);
}

export async function signIn(email, password) {
  return signInWithEmailAndPassword(auth, email, password);
}

export async function logout() {
  return signOut(auth);
}

export function onAuth(callback) {
  return onAuthStateChanged(auth, callback);
}
