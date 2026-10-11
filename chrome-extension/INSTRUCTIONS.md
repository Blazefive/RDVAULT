# Extension Chrome Vault — Instructions (version enrichie)

## Concept

L'extension `vault-autofill-extension/` est une **extension du client Desktop RDVAULT** : elle ne fonctionne
que si le Desktop est lancé et l'utilisateur connecté à Vault. Le token Vault reste dans le Desktop ; l'extension
ne dialogue qu'avec le serveur local `http://127.0.0.1:45678`.

```
┌─────────────────────┐        HTTP local (127.0.0.1:45678)        ┌─────────────────────┐
│  Client Desktop     │ ◄──────────────────────────────────────── │ Extension Chrome    │
│  (Electron)         │   Origin: chrome-extension://<id>          │                     │
│  - Connexion Vault  │   Authorization: Bearer <token>            │ - Détection forms   │
│  - Filtrage par site│ ──────────────────────────────────────►   │ - Auto-remplissage  │
│  - Appairage        │   JSON                                     │ - Popup de statut   │
└─────────────────────┘                                            └─────────────────────┘
```

## Installation

### 1. Lancer le client Desktop

Depuis la racine du projet :

```bash
npm run build      # construit l'application React
npm run electron   # lance l'application Desktop
```

Connectez-vous à Vault dans le Desktop.

### 2. Charger l'extension

1. Ouvrez `chrome://extensions/`
2. Activez le **Mode développeur**
3. **Charger l'extension non empaquetée** → dossier `chrome-extension/vault-autofill-extension` du projet
4. L'extension « Vault Autofill » apparaît

### 3. Appairer l'extension

À la première demande de token, le Desktop affiche une boîte de dialogue identifiant l'extension par son ID
(`chrome-extension://<id>`). Vous avez **60 secondes** pour accepter.

- Popup pendant l'attente : **« Confirmez l'accès dans l'application RDVAULT »**
- Refus : **« Accès refusé dans RDVAULT »** (nouvelle demande possible après une minute)
- Desktop redémarré : l'appairage est perdu, le serveur répond `403 pairing_required` et l'extension redemande
  automatiquement un appairage

## Contrat du serveur sync (127.0.0.1:45678)

Tous les endpoints exigent l'identification de l'extension : en-tête `X-Vault-Extension-Id: <id>` (32 lettres a–p, envoyé par `auth-manager.js` via `chrome.runtime.id`) ou en-tête `Origin: chrome-extension://<id>` quand Chrome l'envoie. Sinon `403`. Note : Chrome n'envoie pas d'en-tête `Origin` vers les hôtes couverts par `host_permissions`, d'où l'en-tête dédié.

| Endpoint | Authentification | Réponse |
|---|---|---|
| `GET /auth/token` | `X-Vault-Extension-Id` (ou `Origin`) + `X-Vault-Extension: rdvault` | `200 {token}` ; `403 {error:'pairing_denied'}` ; `503 {error:'Token not ready'}`. Déclenche la boîte de dialogue d'appairage à la première demande (jusqu'à 60 s : l'extension attend 65 s) |
| `GET /sync` | Bearer + extension appairée | `{connected, vaultUrl, username, timestamp}` — **sans token Vault** ; `{connected:false}` si non connecté |
| `GET /api/secrets?host=<hostname>` | Bearer + appairée | `{success:true, secrets:[{name, engine, username, url, type}]}` — **sans mot de passe ni notes** ; `host` obligatoire (`400` sinon) ; filtrage par hostname côté Desktop |
| `GET /api/secret?host=&engine=&name=` | Bearer + appairée | `{success:true, secret:{name, engine, username, password, url, type}}` ; `404` si le secret ne correspond pas au site |
| `GET /api/totp/<keyName>` | Bearer + appairée | `{success:true, code}` |

Erreurs communes : `403 {error:'pairing_required'}` (extension non appairée → redemander `/auth/token`),
`401` (token manquant/invalide, ou Desktop non connecté à Vault).

### Matching site ↔ secrets (côté Desktop)

Le `host` transmis est toujours le hostname de l'onglet (`sender.tab.url`), jamais une valeur fournie par la page.
Le Desktop compare ce hostname aux champs `URL` / `Website` des secrets :

| Website dans Vault | URL visitée | Match ? |
|---|---|---|
| `github.com` | `https://github.com/login` | Oui |
| `github.com` | `https://www.github.com` | Oui (sous-domaine) |
| `accounts.google.com` | `https://accounts.google.com` | Oui (exact) |
| `accounts.google.com` | `https://mail.google.com` | Non |
| `example.org` | `https://example.com` | Non |
| `github.io` (suffixe public) | `https://projet.github.io` | Non |

## Tests de fonctionnement

Les textes sont cités en français : l'extension s'affiche dans la langue du navigateur
(12 langues, anglais par défaut ; voir « Langues » dans `vault-autofill-extension/README.md`).
Pour la voir en français, choisissez le français comme langue de Chrome (ou lancez Chrome avec `--lang=fr`).

### Test 1 — Statut de connexion (popup)

| Situation | Icône | Texte |
|---|---|---|
| Desktop non lancé | rouge | « Desktop non disponible » |
| Desktop lancé, appairage en attente | orange | « Confirmez l'accès dans l'application RDVAULT » |
| Appairage refusé | rouge | « Accès refusé dans RDVAULT » |
| Desktop lancé, non connecté à Vault | rouge | « Desktop démarré mais non connecté » |
| Desktop connecté | verte | « Desktop connecté » + utilisateur et serveur |

Le popup interroge le background toutes les 10 s (2 s pendant l'appairage).

### Test 2 — Auto-remplissage

1. Dans le Desktop, créez un secret : nom `test-github`, username `monuser@example.com`, un mot de passe,
   **Website : `github.com`**
2. Ouvrez `https://github.com/login`
3. Une icône « V » apparaît sur le champ mot de passe ; cliquez, sélectionnez l'entrée : les champs sont remplis.
   Le mot de passe n'est demandé au Desktop (`/api/secret`) qu'à ce moment.

### Test 3 — TOTP

Si un champ code est détecté après le remplissage (même page ou page suivante, dans les 5 minutes), l'extension
demande `GET /api/totp/<ENGINE>-<nom>` au Desktop et remplit le code.

### Test 4 — Déconnexion

Déconnectez-vous dans le Desktop : le popup passe à « Desktop démarré mais non connecté » et
`/api/secrets` répond `401`.

## Débogage

- Service worker : `chrome://extensions/` → « Inspecter les vues : service worker »
- Popup : clic droit sur l'icône → « Inspecter la fenêtre contextuelle »
- Content script : `F12` sur la page → Console (messages `[Vault …]`)
- API : `http://127.0.0.1:45678/sync` répond `403` depuis un navigateur (Origin non extension) — c'est normal

## Problèmes connus

**« Extension context invalidated »** : l'extension a été rechargée ; rechargez les pages ouvertes.

**Le logo « V » n'apparaît pas** : Desktop connecté ? Secret avec `Website` / `URL` correspondant ? Page en https ?
Champ mot de passe visible ? Formulaire hors iframe (le script n'est pas injecté dans les frames) ?

**« Desktop non disponible »** : Desktop lancé ? Port 45678 libre ?

## Permissions de l'extension

`storage` (token de session, dernier identifiant pour le TOTP sans mot de passe), `alarms` (vérification du token
toutes les minutes), `host_permissions: http://127.0.0.1:45678/*`. Content script sur `https://*/*` uniquement,
`all_frames: false`.
