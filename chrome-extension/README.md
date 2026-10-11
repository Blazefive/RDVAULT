# Vault Autofill - Extension Chrome (version simple)

Extension Chrome (Manifest V3) pour auto-remplir les formulaires web avec vos identifiants stockés dans
HashiCorp Vault. Cette version parle **directement** à Vault (authentification LDAP) ; la version enrichie,
qui passe par l'application Desktop RDVAULT, se trouve dans `vault-autofill-extension/`.

## Fonctionnalités

- Authentification LDAP auprès de votre serveur Vault (**https obligatoire**)
- Détection des champs identifiant / mot de passe (scoring, formulaires dynamiques, shadow DOM ouvert)
- Liste des identifiants du site **sans mot de passe** ; le mot de passe n'est transmis qu'à la sélection
- Cache des secrets en mémoire du service worker (TTL : 5 minutes)
- Support KV v1 et KV v2
- Interface popup pour gérer la connexion et actualiser le cache
- Interface dans la langue du navigateur (`chrome.i18n`, `_locales/`) : les 12 langues de l'application
  (ar, de, en, es, fr, it, ja, ko, pt, ru, tr, zh_CN), anglais par défaut, de droite à gauche en arabe.
  Les libellés cités ci-dessous en français s'affichent traduits

## Installation

1. Ouvrez `chrome://extensions/`
2. Activez le **Mode développeur** (en haut à droite)
3. Cliquez sur **Charger l'extension non empaquetée**
4. Sélectionnez le dossier `chrome-extension` de ce projet

Les icônes attendues dans `icons/` : `icon16.png`, `icon48.png`, `icon128.png`.

### Serveur Vault

Le serveur Vault doit être exposé en **https** avec un certificat reconnu par Chrome : l'extension refuse
toute URL `http://`. Les requêtes sont émises depuis le service worker (couvert par `host_permissions`)
avec l'en-tête `X-Vault-Request: true` ; aucune configuration particulière du serveur Vault n'est requise.

## Utilisation

### 1. Connexion à Vault

1. Cliquez sur l'icône de l'extension dans la barre d'outils
2. Renseignez :
   - **URL Vault** : `https://vault.example.com:8200`
   - **Namespace** : laisser vide si non utilisé
   - **Utilisateur LDAP** / **Mot de passe**
3. Cliquez sur **Se connecter**

Le token Vault est conservé dans `chrome.storage.session` : il disparaît à la fermeture du navigateur.

### 2. Renseigner le champ « Website » de vos secrets

Pour que l'extension associe un secret à un site, ajoutez un champ `Website` (ou `URL`) à vos entrées Vault
avec le domaine du site, par exemple `github.com`.

### 3. Auto-remplissage

1. Visitez une page de connexion **https** (ex. `https://github.com/login`)
2. Si des identifiants correspondent au domaine, une icône bleue « V » apparaît sur le champ mot de passe
   (ou sur le champ identifiant si la page ne contient que celui-ci) ; le menu s'ouvre aussi au focus du champ identifiant
3. Sélectionnez l'identifiant : le mot de passe est alors demandé au service worker et les champs sont remplis

### 4. Actualiser le cache

Après modification de vos secrets dans Vault : popup → **Actualiser le cache**.

## Matching site ↔ secrets

Réalisé dans le service worker, à partir du **hostname de l'onglet** (fourni par Chrome, jamais par la page) :

- **Match exact** : `github.com` ↔ `github.com`
- **Sous-domaines** : `github.com` ↔ `login.github.com`
- Le champ peut contenir une URL complète ou un simple domaine
- Le hostname du secret doit comporter **au moins deux labels** et ne doit pas être un **suffixe public**
  (`com`, `co.uk`, `github.io`, `herokuapp.com`, `vercel.app`, …) : un secret enregistré sur `github.io`
  ne matche jamais `autre-projet.github.io`
- Seules les pages **https** sont prises en compte

Ordre de priorité : champ `Website`, puis champ `URL`.

### Formulaires pris en charge par le content script

| Type de formulaire | Prise en charge |
|---|---|
| Identifiant + mot de passe classique | Oui |
| Connexion en deux étapes (identifiant, puis mot de passe sur une autre vue) | Oui |
| SPA React / Angular / Vue | Oui (setter natif + événements `input` / `change`) |
| Champs dans un shadow DOM **ouvert** | Oui |
| Formulaire dans une **iframe** (même same-origin) | **Non** : injection dans le document principal uniquement (`all_frames: false`) |
| Champ TOTP | **Non** dans cette version (voir la version enrichie) |

## Architecture

```
chrome-extension/
├── manifest.json          # Configuration MV3 (permissions : storage, alarms ; hôtes : https://*/*)
├── background.js          # Service worker : session Vault, cache, matching, SELECT_CREDENTIAL
├── vault-client.js        # Client API Vault (LDAP, KV v1/v2) utilisé par background.js
├── content.js             # Détection des champs, UI en shadow root fermé, remplissage
├── popup.html / popup.js  # Connexion / déconnexion / actualisation du cache
├── _locales/              # Textes de l'interface, 12 langues (chrome.i18n, repli « en »)
└── icons/
```

## Sécurité

- **Token** : `chrome.storage.session` uniquement (non persisté sur disque, effacé à la fermeture du navigateur)
- **https obligatoire** pour l'URL Vault et pour les pages où l'auto-remplissage est proposé
- **Mots de passe** : jamais présents dans la liste envoyée au content script ; renvoyés uniquement pour
  l'entrée sélectionnée (`SELECT_CREDENTIAL`), depuis le cache, pour le hostname de l'onglet
- **UI isolée** dans un shadow root fermé ; les clics et focus synthétiques (`isTrusted === false`) sont ignorés
- **Permissions minimales** : `storage`, `alarms`, `host_permissions: https://*/*` ; pas de `scripting`, `activeTab` ni `update_url`

## Dépannage

**L'icône « V » n'apparaît pas**
1. Vérifiez que vous êtes connecté (popup)
2. Vérifiez que le secret a un champ `Website` / `URL` correspondant au domaine (deux labels minimum)
3. La page doit être en https et contenir un champ mot de passe (ou identifiant) visible
4. Actualisez le cache, puis rechargez la page

**Erreur de connexion**
1. L'URL doit commencer par `https://` et le certificat doit être valide pour Chrome
2. Vérifiez les identifiants LDAP
3. Consultez la console du service worker (`chrome://extensions/` → « Inspecter les vues »)

## Développement

1. Éditez les fichiers dans `chrome-extension/`
2. Dans `chrome://extensions/`, cliquez sur **Recharger** pour l'extension

Logs : service worker via `chrome://extensions/` → « Inspecter les vues » ; content script via `F12` sur la page ;
popup via clic droit sur l'icône → Inspecter.

## Limitations

- Détection heuristique des formulaires (peut échouer sur certains sites)
- Cache de 5 minutes (actualisation manuelle possible)
- Pas de TOTP ni de synchronisation temps réel avec Vault
