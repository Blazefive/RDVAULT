# Extension Chrome RDVAULT — Instructions (version enrichie)

## Concept

L'extension `vault-autofill-extension/` est une **extension de l'application RDVAULT** : elle remplit les
identifiants et gère les passkeys, et ne fonctionne que si RDVAULT est ouvert et déverrouillé (mode local ou
mode entreprise). Les secrets et le jeton Vault restent dans l'application ; l'extension ne dialogue qu'avec le
serveur local `http://127.0.0.1:45678`.

```
┌─────────────────────┐        HTTP local (127.0.0.1:45678)        ┌─────────────────────┐
│  Client Desktop     │ ◄──────────────────────────────────────── │ Extension Chrome    │
│  (Electron)         │   Origin: chrome-extension://<id>          │                     │
│  - Connexion Vault  │   Authorization: Bearer <token>            │ - Détection forms   │
│  - Filtrage par site│ ──────────────────────────────────────►   │ - Auto-remplissage  │
│  - Appairage        │   JSON                                     │ - Popup de statut   │
└─────────────────────┘                                            └─────────────────────┘
```

## Installation (utilisateur)

L'extension est **livrée avec l'installeur RDVAULT** : elle est copiée dans
`C:\Program Files\RDVAULT\resources\chrome-extension`. Chrome n'autorise pas une application à installer une
extension toute seule (hors Chrome Web Store) : il faut la charger **une fois**. RDVAULT guide l'opération dans
**Paramètres › Extension** (dossier, boutons « Ouvrir le dossier », « Copier le chemin » et copie de l'adresse de
la page des extensions).

1. Installez RDVAULT, ouvrez-le et connectez-vous (ou déverrouillez le coffre).
2. Dans RDVAULT : **Paramètres › Extension**. Cliquez sur le bouton `chrome://extensions`
   (ou `edge://extensions`, `brave://extensions`) : l'adresse est copiée. Collez-la dans la barre d'adresse du
   navigateur et validez. (Les navigateurs refusent d'ouvrir cette page depuis une autre application.)
3. Activez le **Mode développeur** (interrupteur en haut à droite de la page).
4. Cliquez sur **Charger l'extension non empaquetée** et choisissez le dossier indiqué dans RDVAULT
   (`C:\Program Files\RDVAULT\resources\chrome-extension`).
5. L'extension « RDVAULT » apparaît (icône RDVAULT ; elle s'appelait « Vault Autofill » avant la 1.7.0).
   Épinglez-la (icône puzzle › épingle) puis ouvrez-la : RDVAULT affiche une boîte de dialogue avec l'identifiant
   de l'extension ; cliquez sur **Autoriser** (60 secondes pour répondre).

L'appairage est mémorisé : il survit aux redémarrages de RDVAULT et aux mises à jour de l'application.

### Mises à jour

Une mise à jour de RDVAULT met aussi à jour les fichiers de l'extension. Chrome ne les relit pas tout seul :
dans la page des extensions, cliquez sur **Recharger** (flèche ronde) sous l'extension RDVAULT.

### Identifiant fixe

Le manifeste contient une clé publique (`key`) : l'extension a le **même identifiant**
(`cndjkmkhndclfcpcgeocmfdjnefhhhba`) sur tous les postes et quel que soit le dossier chargé. Un administrateur peut
donc l'approuver une fois pour toutes et la reconnaître dans les journaux. La clé privée correspondante sert
uniquement à empaqueter l'extension (fichier `.crx`, ou premier dépôt sur le Chrome Web Store pour garder le même
identifiant) : elle n'est **pas** dans le dépôt et doit être conservée à part.

> Passage d'une version antérieure à la 1.7.0 (sans clé fixe) : l'identifiant change une fois. Supprimez
> l'ancienne extension dans `chrome://extensions`, chargez celle de RDVAULT, puis acceptez de nouveau l'appairage.

### Développement

Depuis la racine du projet : `npm run build`, lancer l'application, puis charger le dossier
`chrome-extension/vault-autofill-extension` du projet (mêmes étapes 3 à 5).

### Appairage : comportement détaillé

- Popup pendant l'attente : **« Confirmez l'accès dans l'application RDVAULT »**
- Refus : **« Accès refusé dans RDVAULT »** (nouvelle demande possible après une minute)
- Demande restée sans réponse 60 s (boîte fermée par le délai) : **« Demande d'appairage expirée : rouvrez
  l'extension pour réessayer »**, affiché si la popup est encore ouverte. Ce n'est pas un refus : aucun délai
  de carence. En revanche, l'extension n'envoie plus aucune demande automatique (ouverture d'onglets,
  vérification périodique) tant que la popup n'est pas rouverte, pour que la boîte ne réapparaisse pas toute
  seule. Rouvrir la popup envoie une nouvelle demande.
- Un identifiant déjà approuvé obtient son jeton sans nouvelle question (liste mémorisée dans
  `%APPDATA%\RDVAULT\paired-extensions.json`, supprimée seulement à la désinstallation)

## Contrat du serveur sync (127.0.0.1:45678)

Tous les endpoints exigent l'identification de l'extension : en-tête `X-Vault-Extension-Id: <id>` (32 lettres a–p, envoyé par `auth-manager.js` via `chrome.runtime.id`) ou en-tête `Origin: chrome-extension://<id>` quand Chrome l'envoie. Sinon `403`. Note : Chrome n'envoie pas d'en-tête `Origin` vers les hôtes couverts par `host_permissions`, d'où l'en-tête dédié.

| Endpoint | Authentification | Réponse |
|---|---|---|
| `GET /auth/token` | `X-Vault-Extension-Id` (ou `Origin`) + `X-Vault-Extension: rdvault` | `200 {token}` ; `403 {error:'pairing_denied'}` (refus) ; `403 {error:'pairing_timeout'}` (boîte restée sans réponse 60 s) ; `503 {error:'Token not ready'}`. Déclenche la boîte de dialogue d'appairage à la première demande (jusqu'à 60 s : l'extension attend 65 s) |
| `GET /sync` | Bearer + extension appairée | `{connected, vaultUrl, username, timestamp}` — **sans token Vault** ; `{connected:false}` si non connecté |
| `GET /api/secrets?host=<hostname>` | Bearer + appairée | `{success:true, secrets:[{name, engine, username, url, type}]}` — **sans mot de passe ni notes** ; `host` obligatoire (`400` sinon) ; filtrage par hostname côté Desktop |
| `GET /api/secret?host=&engine=&name=` | Bearer + appairée | `{success:true, secret:{name, engine, username, password, url, type}}` ; `404` si le secret ne correspond pas au site |
| `GET /api/totp/<keyName>` | Bearer + appairée | `{success:true, code}` |

Erreurs communes : `403 {error:'pairing_required'}` (extension non appairée → redemander `/auth/token`),
`401` (token manquant/invalide, ou Desktop non connecté à Vault).

### Matching site ↔ secrets (côté Desktop)

Le `host` transmis est toujours un hostname fourni par Chrome au service worker, jamais une valeur fournie par la
page ou par le script de contenu : celui de l'onglet (`sender.tab.url`) pour un formulaire de la page, celui de la
frame (`sender.url`) pour un formulaire dans une iframe, qui n'obtient ainsi que les secrets de son propre domaine.
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
| Appairage expiré (boîte restée sans réponse 60 s, popup ouverte) | rouge | « Demande d'appairage expirée : rouvrez l'extension pour réessayer » |
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

**Le logo « V » n'apparaît pas** : RDVAULT ouvert et déverrouillé ? Secret avec `Website` / `URL` correspondant ?
Page en https ? Champ mot de passe visible ?

**« Desktop non disponible »** : RDVAULT lancé ? Port 45678 libre ?

**Rien ne change après une mise à jour** : cliquez sur « Recharger » sous l'extension dans `chrome://extensions`.

## Permissions de l'extension

`storage` (token de session, dernier identifiant pour le TOTP sans mot de passe), `alarms` (vérification du token
toutes les minutes), `host_permissions: http://127.0.0.1:45678/*`. Scripts de contenu sur `https://*/*`
uniquement, y compris dans les iframes (`all_frames: true`).
