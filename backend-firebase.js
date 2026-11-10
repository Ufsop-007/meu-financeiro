// Backend de produção: Firebase Auth (login Google) + Cloud Firestore (dados cifrados).
// Contrato usado pelo app: onAuth, signIn, signOut e store {getDoc, setDoc, deleteDoc, createDocIfMissing, listen}.
(function () {
  const cfg = window.MF_CONFIG || {};
  if (!window.firebase || !cfg.FIREBASE_CONFIG) {
    window.MF_BACKEND = null;
    return;
  }
  firebase.initializeApp(cfg.FIREBASE_CONFIG);
  const auth = firebase.auth();
  const db = firebase.firestore();
  const COL = 'casal';
  const ref = id => db.collection(COL).doc(id);
  // Leitura/escrita funcionam offline e sincronizam ao voltar a conexão
  db.enablePersistence({ synchronizeTabs: true }).catch(() => { /* navegador sem suporte: segue online */ });
  auth.getRedirectResult().catch(() => { /* sem retorno de redirecionamento */ });

  window.MF_BACKEND = {
    onAuth(cb) {
      return auth.onAuthStateChanged(u => cb(u ? {
        email: (u.email || '').toLowerCase(),
        name: u.displayName || '',
        photo: u.photoURL || '',
        emailVerified: !!u.emailVerified
      } : null));
    },
    async signIn() {
      const provider = new firebase.auth.GoogleAuthProvider();
      provider.setCustomParameters({ prompt: 'select_account' });
      await auth.setPersistence(firebase.auth.Auth.Persistence.LOCAL);   // continua logado neste aparelho
      try {
        await auth.signInWithPopup(provider);
      } catch (err) {
        // popups bloqueados (comum no celular): entra por redirecionamento
        if (err && (err.code === 'auth/popup-blocked' || err.code === 'auth/operation-not-supported-in-this-environment')) {
          return auth.signInWithRedirect(provider);
        }
        throw err;
      }
    },
    signOut() { return auth.signOut(); },
    store: {
      async getDoc(id) {
        const s = await ref(id).get();
        return s.exists ? s.data() : null;
      },
      setDoc(id, data) { return ref(id).set(data); },
      deleteDoc(id) { return ref(id).delete(); },
      createDocIfMissing(id, data) {
        return db.runTransaction(async t => {
          const s = await t.get(ref(id));
          if (s.exists) return false;
          t.set(ref(id), data);
          return true;
        });
      },
      listen(onChanges, onError, onStatus) {
        return db.collection(COL).onSnapshot({ includeMetadataChanges: true }, snap => {
          const changes = snap.docChanges().map(c => ({ id: c.doc.id, type: c.type, data: c.doc.data() }));
          if (changes.length) onChanges(changes);
          if (onStatus) {
            if (snap.metadata.hasPendingWrites) onStatus('pending');
            else if (snap.metadata.fromCache) onStatus('offline');
            else onStatus('synced');
          }
        }, onError);
      }
    }
  };
})();
