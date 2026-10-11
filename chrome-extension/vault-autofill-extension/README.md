# Vault Autofill (version enrichie) - Extension Chrome

Extension Chrome (Manifest V3) d'auto-remplissage de formulaires de connexion avec les identifiants
stockés dans HashiCorp Vault, **via l'application Desktop RDVAULT**.

L'extension ne parle jamais directement à Vault : elle interroge le serveur local de l'application
Desktop (`http://127.0.0.1:45678`). Le token Vault reste dans le Desktop, jamais dans le navigateur.

## Fonctionnalités

- Appairage sécurisé avec l'application Desktop (confirmation explicite dans RDVAULT à la première connexion)
- Détection intelligente des champs login / mot de passe / TOTP (scoring, formulaires dynamiques, Shadow DOM)
- Liste des identifiants du site courant **sans mot de passe** ; le mot de passe n'est récupéré qu'à la sélection
- Remplissage des codes TOTP (même page ou page suivante)
- Interface (icône « V » + menu) isolée dans un shadow root fermé, inaccessible aux scripts de la page
- Popup d'état de la connexion Desktop
- Interface en 12 langues (voir « Langues »)

## Langues

L'extension suit la **langue du navigateur** (`chrome.i18n`), indépendamment de la langue choisie
dans l'application Desktop : arabe, allemand, anglais, espagnol, français, italien, japonais, coréen,
portugais (Brésil et Portugal), russe, turc et chinois simplifié — les 12 langues de l'application.
Une autre langue (ou le chinois traditionnel) s'affiche en anglais (`"default_locale": "en"`).
En arabe, le menu, la popup et la fenêtre passkey s'affichent de droite à gauche.

Tout ce qui est affiché est traduit : popup, infobulle et menu d'autoremplissage, messages d'erreur du
service worker et fenêtre de choix des passkeys affichée sur les sites. Les textes sont dans
`_locales/<langue>/messages.json` ; chaque appel du code porte aussi le texte français d'origine,
utilisé seulement hors navigateur (tests) et identique à `_locales/fr`. Les noms des messages et
leurs espaces réservés doivent rester identiques dans les 12 fichiers :

```bash
node --test test/extension/i18n-locales.test.js     # parité des 12 langues, code ↔ messages, rendu (jsdom)
E2E_BROWSER=<chrome.exe> node --test test/extension/i18n-browser.test.js   # vrai Chrome en --lang=en, fr, ar
```

## Pré-requis

- Application Desktop RDVAULT lancée et utilisateur connecté à Vault
- Chrome / Chromium récent (Manifest V3)

## Installation

1. Ouvrez `chrome://extensions/`
2. Activez le **Mode développeur**
3. Cliquez sur **Charger l'extension non empaquetée**
4. Sélectionnez le dossier `chrome-extension/vault-autofill-extension` du projet

## Appairage à la première connexion

À la première demande de token par l'extension, l'application Desktop affiche une boîte de dialogue
d'approbation identifiant l'extension par son ID (`chrome-extension://<id>`). Vous disposez de 60 secondes
pour accepter.

- Pendant l'attente, le popup affiche **« Confirmez l'accès dans l'application RDVAULT »**
- Si vous refusez, le popup affiche **« Accès refusé dans RDVAULT »** ; une nouvelle demande est possible après une minute
- Une fois accepté, le token est conservé en `chrome.storage.session` (effacé à la fermeture du navigateur)

Le token est vérifié toutes les minutes via `chrome.alarms` (compatible avec la mise en veille du service worker MV3).

Si le Desktop est redémarré, l'appairage est perdu : le serveur répond `403 {error:'pairing_required'}`,
l'extension oublie son token et redemande automatiquement un appairage (nouvelle boîte de dialogue dans RDVAULT).

## Flux de fonctionnement

```
Page https://site.example/login
   │
   │ content.js détecte les champs et affiche l'icône « V »
   ▼
background.js ── GET /api/secrets?host=site.example ──► Desktop RDVAULT
   ◄── {secrets:[{name, engine, username, url, type}]}   (SANS mot de passe)
   │
   │ l'utilisateur choisit une entrée dans le menu
   ▼
background.js ── GET /api/secret?host=…&engine=…&name=… ──► Desktop RDVAULT
   ◄── {secret:{…, password}}
   │
   ▼
content.js remplit username + password, puis surveille un champ TOTP
   (GET /api/totp/<clé> si un champ code est détecté)
```

Points clés :

- Le **hostname** transmis au Desktop est toujours celui de l'onglet (`sender.tab.url`), jamais une valeur
  fournie par la page ou le content script.
- Le **matching site ↔ secrets est effectué côté Desktop** (paramètre `host` obligatoire). L'extension ne
  contient plus de logique de comparaison de domaines.
- Le content script ne reçoit jamais la liste des mots de passe : il ne demande que celui de l'entrée sélectionnée
  (`SELECT_CREDENTIAL`), l'utilise pour le remplissage et ne le conserve pas.
- Les identifiants renvoyés au Desktop (nom d'entrée, coffre, clé TOTP) sont transmis **tels quels** : jamais
  raccourcis ni débarrassés de leurs espaces, puisque le Desktop retrouve l'entrée par égalité stricte. Une entrée
  dont le nom commence ou finit par une espace est donc remplie normalement. Un identifiant vide, trop long
  (nom d'entrée : 512 caractères, coffre et clé TOTP : 256) ou contenant un caractère de contrôle est écarté.
- Le code TOTP d'une entrée rangée dans un dossier (nom de clé contenant `/`) est servi normalement.
- Seules les pages **https** sont prises en charge.

## Endpoints Desktop utilisés

| Endpoint | Auth | Rôle |
|---|---|---|
| `GET /auth/token` | En-têtes `X-Vault-Extension-Id` (identifiant de l'extension) + `X-Vault-Extension: rdvault` | Obtention du token (déclenche l'appairage la première fois). Réponses : 200 `{token}`, 403 `{error:'pairing_denied'|'pairing_required'}`, 503 `{error:'Token not ready'}` |
| `GET /sync` | Bearer | État de connexion (`connected`, `vaultUrl`, `username`) |
| `GET /api/secrets?host=<hostname>` | Bearer | Liste des secrets correspondant au site, sans mot de passe ni notes |
| `GET /api/secret?host=&engine=&name=` | Bearer | Secret complet (404 si non lié au site) |
| `GET /api/totp/<keyName>` | Bearer | Code TOTP |

## Utilisation

1. Lancez RDVAULT Desktop et connectez-vous à Vault
2. Cliquez sur l'icône de l'extension : le statut doit être **« Desktop connecté »** (acceptez l'appairage si demandé)
3. Dans le Desktop, renseignez le champ **Website** (ou **URL**) de vos secrets avec le domaine du site
4. Visitez la page de connexion du site (https) : une icône « V » apparaît sur le champ mot de passe ;
   le menu s'ouvre aussi au focus du champ identifiant
5. Sélectionnez l'entrée souhaitée : les champs sont remplis

La liste des identifiants d'un site est rechargée au plus toutes les 60 secondes, ou au premier focus
d'un nouveau champ identifiant. Une page (ou une frame) sans aucun champ de saisie n'interroge pas
RDVAULT. Si le chargement échoue (RDVAULT verrouillé ou injoignable, limite de débit du serveur local),
l'échec n'est pas mémorisé comme « aucun identifiant » : de nouvelles tentatives sont faites pendant
environ 2 min 30 (2 s, 4 s, 8 s, 15 s, 30 s, 30 s, 60 s), si bien qu'une page de connexion ouverte avant
le déverrouillage de RDVAULT propose ses identifiants dès le déverrouillage, sans rechargement.

### Formulaires pris en charge

| Type de formulaire | Prise en charge |
|---|---|
| Identifiant + mot de passe classique | Oui |
| Connexion en deux étapes (identifiant, puis mot de passe sur une autre vue) | Oui : icône sur le champ identifiant seul, puis sur le champ mot de passe de la vue suivante |
| SPA React / Angular / Vue | Oui : setter natif + événements `input` / `change` |
| Champs dans un shadow DOM **ouvert** | Oui : parcours récursif des shadow roots |
| Champ TOTP (même page ou page suivante) | Oui (`GET /api/totp/<clé>`) |
| Champ à « étiquette flottante » transparent (`opacity: 0`) tant qu'il est vide (ex. login.orange.fr) | Oui, s'il est réellement atteignable au clic (test de `elementFromPoint` en son centre, taille de vrai champ) ; les pièges transparents non cliquables restent ignorés |
| Formulaire dans une **iframe** (même d'un autre domaine, ex. idmsa.apple.com dans account.apple.com) | Oui (`all_frames: true`) : les identifiants proposés sont filtrés sur l'hôte de **la frame** (`sender.url` fourni par Chrome), jamais sur celui de la page hôte ; une iframe tierce n'obtient que les secrets de son propre domaine |

## Permissions

| Permission | Usage |
|---|---|
| `storage` | Token de session (`chrome.storage.session`) et dernier identifiant utilisé pour le TOTP (nom / engine uniquement) |
| `alarms` | Vérification périodique du token |
| `host_permissions: http://127.0.0.1:45678/*` | Serveur local du Desktop uniquement |

Le content script est déclaré sur `https://*/*` seulement.

## Architecture

```
vault-autofill-extension/
├── manifest.json     # Configuration MV3
├── background.js     # Service worker : appairage, /api/secrets, /api/secret, TOTP
├── auth-manager.js   # Gestion du token (fetch 65 s pour l'appairage, chrome.alarms)
├── content.js        # Détection des champs, UI en shadow root fermé, remplissage
├── passkey-*.js      # Passkeys (voir PASSKEYS.md)
├── popup.html / js   # État de la connexion Desktop (rafraîchi toutes les 10 s)
├── _locales/         # Textes de l'interface, 12 langues (chrome.i18n)
└── icons/
```

## Sécurité

- Aucun secret n'est stocké de façon persistante dans le navigateur
- Les mots de passe ne transitent vers la page qu'au moment du remplissage, à la demande explicite de l'utilisateur
- Les événements de clic / focus synthétiques (`isTrusted === false`) sont ignorés par l'UI de l'extension
- Le dernier identifiant mémorisé pour le TOTP ne contient que `{name, engine, totpKey, hostname, savedAt}`
  et expire après 5 minutes
- Les messages sensibles envoyés depuis une page non https sont rejetés par le background

## Dépannage

Les messages ci-dessous sont cités en français ; ils s'affichent dans la langue du navigateur.

**« Desktop non disponible »** : vérifiez que RDVAULT Desktop est lancé et que le port 45678 est libre.
Si le port est déjà pris (autre programme, ou RDVAULT ouvert dans une autre session Windows du même poste),
l'application affiche au démarrage l'avertissement « Extension Chrome non reliée » : l'autoremplissage n'est
alors pas relié à son coffre.

**Poste partagé par plusieurs sessions Windows** (bureau à distance, Citrix, changement rapide d'utilisateur) :
le port 45678 est commun à toutes les sessions. Seule la première instance RDVAULT l'écoute, et l'extension
d'une autre session joindrait l'application de la première. N'utilisez pas l'extension enrichie sur un tel poste
(voir `SECURITY.md`).

**L'extension se retrouve déconnectée** alors que RDVAULT est ouvert : si l'interface de l'application a planté
ou a été rechargée, l'état servi à l'extension est effacé aussitôt (mesure de sécurité). Reconnectez-vous dans
RDVAULT ; après un plantage, relancez d'abord l'application.

**« Confirmez l'accès dans l'application RDVAULT »** : une demande d'appairage attend votre réponse dans le Desktop.

**« Accès refusé dans RDVAULT »** : l'appairage a été refusé ; attendez une minute et relancez la demande
(ouvrez à nouveau le popup) puis acceptez dans le Desktop.

**L'icône « V » n'apparaît pas** : le site doit être en https, le secret doit avoir un champ Website / URL
correspondant au domaine, et la page doit contenir un champ mot de passe visible.

Logs : service worker via `chrome://extensions/` → « Inspecter les vues », content script via la console de la page (F12).
