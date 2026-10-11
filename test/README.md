# Tests RDVAULT

Trois niveaux, du plus rapide au plus complet. Tous s'exécutent sur une base de données et un profil **temporaires** : ils ne touchent jamais à vos données.

## 1. Unitaires

```bash
npm test                # enchaîne les cinq suites ci-dessous
npm run test:react      # React (Jest)
npm run test:electron   # modules du processus principal (node --test)
npm run test:passkey    # passkeys (node --test) : moteur FIDO2, règle rp.id, parcours WebAuthn complet
npm run test:extension  # extension (node --test) : codes TOTP, traductions des 12 langues, noms d'entrée
npm run test:installer  # installeur NSIS (node --test) : banc d'essai isolé, identité de RDVAULT.exe
```

- `test:electron` : tous les fichiers `electron/**/*.test.js`, dont `configLoader.test.js` (validation des valeurs, `config.cfg` en UTF-16 LE/BE avec ou sans BOM et `config.json` avec BOM lus correctement, avertissement si aucune clé n'est reconnue), `cliServer.session.test.js` (`cli/session.json` supprimé à l'arrêt seulement s'il appartient au processus), `sshBroker.test.js` (serveur SSH en mémoire) et `knownHosts.test.js`. Les dossiers temporaires de ces deux derniers (`%TEMP%\rdvault-kh-*`) sont supprimés en fin de test.
- `test:passkey` : `test/passkey/core.test.js` (crypto, attestation, signature, relais inject/pont simulés), `rpid-policy.test.js` (même règle rp.id dans le pont et le service worker) et `webauthn-flow.test.js` (scripts réels inject ↔ pont ↔ cœur dans jsdom, fenêtre de consentement cliquée : drapeau UV posé quand le coffre est déverrouillé et `userVerification: 'required'` servi par RDVAULT, coffre verrouillé, compteur réservé entre onglets, `excludeCredentials`, ES256, iframes, objets `toJSON`).
- `test:extension` : `test/extension/totp-digits.test.js`, `i18n-locales.test.js` (parité des 12 langues des deux extensions, clés du code ↔ `_locales`, repli français identique, rendu jsdom de la fenêtre passkey et des popups) et `entry-name.test.js` (noms d'entrée et de clé TOTP transmis sans altération par le service worker, `background.js` chargé dans un contexte vm).
- `test:installer` : `test/installer/installer-nsis.test.js` compile les macros **réelles** d'`assets/installer.nsh` dans un installeur minimal qui reproduit l'ordre d'electron-builder (`test/installer/nsis-bench.js`) : `/S /CONFIG=` lu et copié tel quel, `/MODE=`, mise à jour qui conserve `config.cfg` et l'appairage (y compris depuis le désinstalleur 1.7.0, `fixtures/installer-1.7.0.nsh`), vraie désinstallation. Tout se passe dans un bac à sable : dossiers système redirigés, registre et lancement de programmes refusés, aucun installeur RDVAULT réel exécuté. `exe-identity.test.js` vérifie l'édition des ressources de version de `RDVAULT.exe` sans signature (copie d'un petit exécutable). Environ 15 s sous Windows ; chaque test est ignoré si makensis, ses plugins ou l'outil winCodeSign ne sont pas dans le cache d'electron-builder (`%LOCALAPPDATA%\electron-builder\Cache`), sans rien télécharger.
- Tests de l'extension dans un **vrai Chrome** (ignorés sans `E2E_BROWSER`, hors `npm test`) :

  ```bash
  npm run test:extension:browser   # i18n-browser.test.js (--lang en/fr/ar) + honeypot-visibility.test.js
  ```

## 2. Fumée Electron (sans interface)

Tests de fumée (coffre local, sync, adversarial, ssh+winrm — userData temporaire). Lance le vrai code du processus principal dans Electron, sans fenêtre utile, et enchaîne quatre suites :

- **coffre local** (`smoke-localvault.js`) : premier démarrage (`GET /v1/sys/init` sans jeton, confirmation du mot de passe exigée pour créer le premier compte), login, chiffrement AAD, versions, soft-delete, check-and-set (`options.cas` comme Vault KV v2), TOTP, propriété, une seule version conservée pour les blobs internes `.rdvault-*`, effacement physique sur disque (base et journal WAL) après destruction d'un secret, suppression d'un coffre et suppression ou remplacement d'une graine TOTP, historique des entrées normales intact ;
- **serveur de synchronisation** (`smoke-sync.js`) : appairage, en-têtes, refus, aucune donnée sur disque ;
- **suite adversariale** (`smoke-adversarial.js`) : injection, concurrence (écritures simultanées d'un blob `.rdvault-*`, créations simultanées d'une entrée avec `cas=0`, créations simultanées du premier compte), unicode, codes HTTP, `sanitizeHttpsUrl` ;
- **agent SSH / broker WinRM** (`smoke-ssh-agent.js`).

```bash
npm run test:smoke
```

Prérequis : `npm install` (le script `postinstall` recompile `better-sqlite3` pour Electron).

## 3. Bout en bout (extension Chrome + application réelle)

`test/e2e/run.js` pilote **Chrome for Testing** avec l'extension chargée, un site HTTPS local (`test/e2e/site/`) et l'application RDVAULT réelle en mode local pilotée par le protocole DevTools. Il parcourt quinze pages de formulaires : classique, deux étapes, SPA, shadow DOM, pièges invisibles, attributs illisibles, inscription à ne pas remplir, étiquette flottante, pots de miel cachés, pots de miel « sr-only », mot de passe + confirmation, adresse d'envoi dont seule la chaîne de requête contient un mot d'inscription (connexion à remplir), chemin d'envoi `/account/register` (inscription), TOTP sans clé et TOTP à 8 chiffres. S'y ajoutent deux pages sans formulaire (aucune icône ; page et 4 iframes sans aucune requête vers RDVAULT), le refus des événements synthétiques et l'extension « simple » (`chrome-extension/content.js`) sur sept de ces pages.

Tous les tests qui lancent l'application (`run.js`, `app-ui.js`, `features.js`, `passkey.js`, `real-sites.js`, `diag-fields.js`) attendent d'abord que le port de synchronisation `45678` soit libre (trois nouveaux essais espacés de 60 s), sinon refusent de démarrer ; une fois l'application lancée, ils vérifient qu'elle seule tient ce port (`netstat -ano` sous Windows, `lsof` ailleurs) et s'arrêtent sinon. L'extension de test, chargée depuis le dossier du projet, a le même identifiant qu'une installation manuelle : sans cette garde, une instance RDVAULT déjà ouverte et appairée lui servirait ses propres identifiants, et `passkey.js` pourrait écrire ses passkeys dans le vrai coffre. `passkey.js` revérifie aussi que le port est libre juste avant son cas « coffre indisponible », le seul où l'extension tourne sans l'application de test. `app-ui.js` ne charge pas d'extension, mais la garde évite l'avertissement « port occupé » de l'application de test. Fermez RDVAULT avant de lancer ces tests.

`test/e2e/app-ui.js` teste l'interface de l'application : premier démarrage (écran de création du compte administrateur, confirmation différente refusée, création, puis formulaire de connexion habituel), arborescence, recherche, création et édition d'entrées, suppression douce, export/import CSV et XML avec aller-retour exact, déconnexion.

```bash
# Une fois : Chrome for Testing (Google Chrome ≥ 137 refuse --load-extension)
npx @puppeteer/browsers install chrome@stable

# Build React requis
npm run build

# Extension (indiquer le chemin de chrome.exe téléchargé ci-dessus)
set E2E_BROWSER=C:\chemin\vers\chrome-win64\chrome.exe
npm run test:e2e

# Interface de l'application (aucun navigateur externe requis)
npm run test:e2e:ui

# Avec la même variable E2E_BROWSER :
npm run test:e2e:features   # connexion en deux pages + saisie automatique du code TOTP
npm run test:e2e:passkey    # passkeys stockées dans le coffre (création, authentification, garde-fous,
                            # serveur exigeant UV, une seule version du blob des passkeys)
npm run test:e2e:sites      # vrais sites publics (réseau requis, aucun vrai compte ni soumission)

# Diagnostic des champs de sites réels (rien n'est rempli), sans script npm :
node test/e2e/diag-fields.js github,yahoo
```

Les scripts qui chargent l'extension (`run.js`, `features.js`, `passkey.js`, `real-sites.js`, `diag-fields.js`) sortent avec le code 2 sans `E2E_BROWSER`. Tous sortent avec le code 1 s'ils refusent de démarrer parce que le port `45678` est occupé ou s'il n'est pas tenu par l'application de test. Pour `run.js`, `app-ui.js`, `features.js`, `passkey.js` et `diag-fields.js`, toute erreur ou tout contrôle en échec donne aussi le code 1.

`test:e2e:sites` sort avec le code 1 si rien n'a été testé (erreur globale, aucun site, aucun site OK) ou si l'entrée factice d'un site manque dans le menu ; seule cette entrée factice est cliquée. Les murs anti-robot et les écarts propres à un site (pages de tiers qui changent) sont seulement rapportés dans le résumé.

Les tests qui pilotent l'application (`run.js`, `app-ui.js`, `features.js`, `passkey.js`, `real-sites.js`, `diag-fields.js`) partagent `test/e2e/app-helpers.js` : lanceur de l'application, garde du port de synchronisation, connexion par l'interface et nettoyage. Ils créent le premier compte par l'API du coffre local, avec la confirmation du mot de passe exigée au premier démarrage. Si l'écran de connexion était déjà affiché en mode création, la page est rechargée avant la connexion. Ils ne réécrivent `config.cfg` que s'il diffère de `APP_MODE=local` / `LANG=fr`, et le restaurent à la fin. Ils suppriment leur dossier temporaire (`%TEMP%\rdvault-e2e-*`, `rdvault-ui-*`, `rdvault-feat-*`, `rdvault-pk-*`, `rdvault-real-*`, `rdvault-diag-*`) ; en cas d'échec, `run.js` et `app-ui.js` le conservent et affichent le chemin de `app.log`, et `real-sites.js` copie `app.log` à côté de ses captures (`%TEMP%\rdvault-real-sites`) après une erreur globale. Les captures d'écran d'`app-ui.js` restent dans `%TEMP%\rdvault-e2e-shots`.

Variables utiles :

- `E2E_DEBUG=1` affiche les consoles de la page et du service worker de l'extension.
- `E2E_APP_WRAPPER` (tests qui pilotent l'application) remplace `test/e2e/app-wrapper.js` par un autre script de lancement, par exemple pour charger un renderer construit ailleurs que dans `build/`.

Le certificat `test/e2e/cert.pem` est auto-signé pour `localhost` et ne sert qu'au site de test.
