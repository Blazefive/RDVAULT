# Extension Chrome Vault - Instructions

## 🎯 Concept

L'extension Chrome est maintenant une **extension pure du client Desktop**. Elle ne fonctionne **que si le client Desktop est lancé et connecté**.

### Architecture

```
┌─────────────────────┐
│  Client Desktop     │
│  (Electron)         │
│                     │
│  ✓ Connexion Vault  │
│  ✓ Gestion secrets  │
│  ✓ Serveur HTTP     │
│     (port 45678)    │
└──────────┬──────────┘
           │
           │ HTTP API
           │
┌──────────▼──────────┐
│ Extension Chrome    │
│                     │
│  ✓ Détection forms  │
│  ✓ Auto-remplissage │
│  ✓ Affiche statut   │
└─────────────────────┘
```

## 📋 Installation

### 1. Préparer le Client Desktop

```bash
cd C:\Users\rdekien\OneDrive - Groupe Profession Santé\Documents\VAULT

# Construire l'application React
npm run build

# Lancer l'application Desktop
npm run electron
```

### 2. Charger l'Extension Chrome

1. Ouvrez Chrome et allez à : `chrome://extensions/`
2. Activez le **Mode développeur** (coin supérieur droit)
3. Cliquez sur **Charger l'extension non empaquetée**
4. Sélectionnez le dossier :
   ```
   C:\Users\rdekien\OneDrive - Groupe Profession Santé\Documents\VAULT\chrome-extension\vault-autofill-extension
   ```
5. L'extension "Vault Autofill" devrait apparaître

## ✅ Test de Fonctionnement

### Test 1 : Vérifier le Statut de Connexion

1. **Ouvrez le popup de l'extension** (cliquez sur l'icône dans Chrome)
2. **Sans Desktop lancé** :
   - 🔴 Icône rouge
   - Texte : "Desktop non disponible"
   - Message : "Lancez l'application Desktop..."

3. **Lancez le Desktop** mais ne vous connectez pas
   - 🔴 Icône rouge
   - Texte : "Desktop démarré mais non connecté"

4. **Connectez-vous dans le Desktop**
   - 🟢 Icône verte avec effet lumineux
   - Texte : "Desktop connecté"
   - Affiche : Utilisateur et serveur Vault
   - Message : "✓ Auto-remplissage actif"

### Test 2 : Auto-remplissage

1. **Dans le Desktop**, créez un secret :
   - Nom : `test-github`
   - Username : `monuser@example.com`
   - Password : `MonMotDePasse123`
   - Website : `github.com` ⚠️ **Important : remplir ce champ !**

2. **Allez sur** : `https://github.com/login`

3. **Vérifiez** :
   - Un logo "V" bleu devrait apparaître sur le champ password
   - Cliquez dessus
   - Sélectionnez votre credential
   - Les champs username et password sont remplis automatiquement

### Test 3 : Matching d'URL

L'extension match les URLs de manière intelligente :

| Website dans Vault | URL visitée | Match ? |
|-------------------|-------------|---------|
| `github.com` | `https://github.com/login` | ✅ |
| `github.com` | `https://www.github.com` | ✅ |
| `google.com` | `https://accounts.google.com` | ✅ |
| `example.org` | `https://example.com` | ❌ |

### Test 4 : Déconnexion

1. **Dans le Desktop**, cliquez sur **Se déconnecter**
2. **Vérifiez l'extension** :
   - Le statut passe à "Desktop démarré mais non connecté"
   - L'icône devient rouge
   - L'auto-remplissage ne fonctionne plus

## 🔧 Débogage

### Vérifier l'API Desktop

Ouvrez dans un navigateur : `http://127.0.0.1:45678/sync`

**Connecté** :
```json
{
  "connected": true,
  "vaultUrl": "http://192.168.1.15:8200",
  "token": "hvs.CAES...",
  "username": "votre-username",
  "timestamp": 1234567890
}
```

**Déconnecté** :
```json
{
  "connected": false
}
```

### Console de l'Extension

1. Clic droit sur l'icône de l'extension → **Inspecter la fenêtre contextuelle**
2. Onglet **Console** pour voir les erreurs

### Console du Content Script

1. Sur une page web, appuyez sur **F12**
2. Onglet **Console**
3. Recherchez les messages commençant par `[Vault Autofill]`

## 📝 Fichiers Modifiés

### Extension Chrome

- ✅ `popup.html` - Interface simplifiée (statut uniquement)
- ✅ `popup.js` - Vérifie la connexion Desktop toutes les 2s
- ✅ `background.js` - Récupère les secrets via API Desktop
- ✅ `manifest.json` - Permissions minimales (plus de storage)
- ✅ `content.js` - Inchangé (détection et auto-remplissage)

### Client Desktop

- ✅ `electron/main.js` - Ajout endpoint `/api/secrets`
- ✅ `electron/preload.js` - Ajout API IPC pour secrets
- ✅ `src/App.jsx` - Gestionnaire IPC pour fournir secrets

## ⚡ Avantages de cette Architecture

1. **Sécurité** : Le token Vault reste dans le Desktop, jamais dans le navigateur
2. **Simplicité** : Pas de gestion d'authentification dans l'extension
3. **Synchronisation** : Toujours à jour avec le Desktop (pas de cache)
4. **Moins de permissions** : L'extension n'a plus besoin de `storage` ni `alarms`
5. **UX cohérente** : Une seule connexion dans le Desktop

## 🚨 Limitations

- **L'extension ne fonctionne PAS sans le Desktop**
- Le Desktop doit rester lancé pour l'auto-remplissage
- Fonctionne uniquement sur `localhost` (127.0.0.1:45678)

## 🐛 Problèmes Connus

### "Extension context invalidated"

**Cause** : L'extension a été rechargée

**Solution** : Fermez et rouvrez les pages web où l'extension est active

### Le logo "V" n'apparaît pas

**Vérifications** :
1. ✅ Desktop lancé et connecté ?
2. ✅ Secret a un champ "Website" rempli ?
3. ✅ Le Website correspond à l'URL actuelle ?
4. ✅ Console (F12) : erreurs JavaScript ?

### "Desktop non disponible"

**Vérifications** :
1. ✅ Desktop lancé avec `npm run electron` ?
2. ✅ Port 45678 libre ? (pas d'autre instance)
3. ✅ `http://127.0.0.1:45678/sync` répond ?

## 💡 Conseils d'Utilisation

### Organisation des Secrets

Utilisez le champ **Website** pour tous vos secrets :

```
Nom      : github-account
Username : user@example.com
Password : ********
Website  : github.com          ← Important !
URL      : https://github.com  ← Optionnel
Notes    : Compte principal
```

### Domaines vs Sous-domaines

Le matching est flexible :

- `github.com` → match `github.com`, `www.github.com`, `gist.github.com`
- `accounts.google.com` → match uniquement `accounts.google.com`

### Workflow Recommandé

1. Gardez le Desktop **toujours ouvert** pendant votre session
2. Créez vos secrets dans le Desktop
3. Naviguez normalement, l'extension propose automatiquement les credentials
4. Déconnectez-vous du Desktop à la fin de votre session

## 📞 Support

Si l'extension ne fonctionne pas :

1. Vérifiez la console du Desktop (erreurs Electron)
2. Vérifiez la console de l'extension (F12 sur popup)
3. Testez l'API manuellement : `http://127.0.0.1:45678/sync`
4. Rechargez l'extension dans `chrome://extensions/`

---

**Version** : 1.0.0
**Date** : 2025
**Auteur** : Assistant Claude
