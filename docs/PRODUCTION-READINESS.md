# Feuille de route — RDVAULT en produit public professionnel

État au 2026-10-10 (v1.7.0). Ce document distingue ce qui est **fait dans le code** de ce qui
demande une **action externe** (certificat, compte de store, serveur) que le code ne peut pas réaliser seul.

## ✅ Fait (v1.7.0)

- **KDF mémoire-dur (scrypt)** pour les nouveaux coffres, avec rétrocompatibilité totale des coffres PBKDF2 existants (aucune migration forcée, aucun risque de verrouillage). `electron/localVault/crypto.js`.
- **Audit de santé des mots de passe** : détection des mots de passe faibles et réutilisés (hors ligne) + vérification de fuite Have I Been Pwned en k-anonymity (opt-in). `src/utils/passwordHealth.js`, `src/components/PasswordHealthModal.jsx`.
- **Mécanisme de mise à jour automatique** câblé (electron-updater), inerte tant que la dépendance n'est pas installée ni l'app empaquetée. `electron/autoUpdater.js`, liaison `electronUpdater` dans le preload, toast d'information côté renderer.
- **Configuration de distribution** : bloc `publish` (GitHub) dans `electron-builder.json`.
- **Documents de confiance** : `SECURITY.md` (divulgation responsable), `PRIVACY.md` (application et deux extensions, emplacement de toutes les données locales), `docs/THREAT-MODEL.md`, `.well-known/security.txt`, licence MIT (`LICENSE`).
- **Chaîne d'approvisionnement** : génération de SBOM CycloneDX (`npm run sbom`), workflow CI (`.github/workflows/ci.yml`) exécutant lint, audit des dépendances (non bloquant : `npm audit --omit=dev || true`, voir « Vulnérabilités de dépendances » ci-dessous), tests React/Electron/passkeys et tests de fumée.
- **Tests** : tests unitaires du KDF (scrypt + rétrocompat PBKDF2) et de l'audit (k-anonymity vérifié). Suite de fumée mise à jour (schéma v3, colonne `kdf`, connexion d'un compte hérité).
- **Installeur et mises à jour** (`assets/installer.nsh`, `electron-builder.json`) :
  - **une mise à jour conserve la configuration** : silencieuse ou interactive, elle garde `config.cfg` à l'octet près (dont `TRUSTED_CERT_FINGERPRINTS`, `LANG` et les commentaires), `config.json` s'il existe et l'appairage de l'extension (`%APPDATA%\RDVAULT\paired-extensions.json`). Avant, chaque mise à jour remettait les valeurs d'exemple et désappairait l'extension. L'assistant présélectionne le mode courant et ne réécrit que les valeurs modifiées. C'était un prérequis de la mise à jour automatique, qui sera silencieuse ;
  - installation silencieuse `/S /CONFIG=fichier.cfg` : fichier copié tel quel (il était ignoré) ; `/MODE=` ne remplace que `APP_MODE` ; fichier illisible ou mode invalide : arrêt (code 2) sans modification ;
  - désinstallation : configuration, session CLI et appairage supprimés ; base chiffrée `local-vault.db`, journal d'audit de la CLI, `known_hosts.json` et profil de l'interface conservés (suppression complète décrite dans `PRIVACY.md`) ; l'entrée des applications installées est bien retirée ;
  - `RDVAULT.exe` porte ses informations de version (nom de produit, société, version, marque) : `win.signAndEditExecutable` est déjà à `true`, sans certificat requis (sans `CSC_LINK`, electron-builder saute la signature et n'édite que les ressources de version) ;
  - tests : `npm run test:installer`, enchaîné par `npm test` (environ 15 s sous Windows). `test/installer/installer-nsis.test.js` compile les macros réelles d'`assets/installer.nsh` dans un banc isolé (`/S /CONFIG=`, `/MODE=`, mise à jour depuis la 1.7.0 qui conserve configuration et appairage, désinstallation), sans toucher au registre, à Program Files ni au vrai `%APPDATA%\RDVAULT` ; `test/installer/exe-identity.test.js` vérifie la configuration (édition des ressources, aucune signature exigée) et applique la commande d'electron-builder à la copie d'un petit exécutable. Chaque test est ignoré si `makensis`, ses plugins ou l'outil winCodeSign manquent dans le cache d'electron-builder (rien n'est téléchargé).
- **Premier démarrage du coffre local** : `GET /v1/sys/init` (`{ initialized }`, comme Vault) dans `electron/localVault/localVaultServer.js` ; l'écran de création du compte administrateur (confirmation du mot de passe maître, 8 caractères minimum, indicateur de force) s'affiche, et le serveur exige la confirmation pour créer le premier compte.
- **Configuration en UTF-16** : `config.cfg` / `config.json` en UTF-16 LE ou BE (avec ou sans BOM) ou en UTF-8 avec BOM sont lus correctement, avec un avertissement dans le journal (`electron/configLoader.js`, `decodeConfigBuffer`).
- **Effacement physique** (coffre local) : point de contrôle `wal_checkpoint(TRUNCATE)` après la destruction d'une entrée, la suppression d'un coffre, la suppression ou le remplacement d'une graine TOTP et la purge des versions des blobs cachés `.rdvault-*` (`electron/localVault/secretsService.js`, `totpService.js`). Coût mesuré : environ 7 ms par effacement définitif sur une base de 38 Mio.
- **Copies et déplacements sans écrasement** : Migrer, Copier, Déplacer et le glisser-déposer écrivent à destination avec `cas: 0` (création seule, appliquée par Vault KV v2 et par le coffre local ; `src/hooks/useMigration.js`) ; une entrée créée entre-temps par un autre poste n'est pas remplacée.
- **Compatibilité ascendante** : un coffre créé par la 1.5.0 s'ouvre à l'identique (entrées, versions, TOTP, passkeys), vérifié par un banc qui recrée des coffres avec le serveur du coffre local extrait de l'installeur 1.5.0. Les passkeys d'un compte 1.5.0 dont le nom contient `@`, une espace ou un accent sont de nouveau disponibles (`src/utils/passkeyEngine.js`). Ce banc n'est pas dans le dépôt ; les cas des passkeys et des noms `.rdvault…` sont couverts par des tests Jest (`src/utils/passkeyEngine.compat150.test.js`, `src/hooks/useSecrets.reservedNames.test.js`).

## ⚠️ Actions externes requises (ne peuvent pas être faites par le code seul)

### 1. Signature de code (priorité n° 1)
Sans signature, SmartScreen avertit à chaque installation **et à chaque mise à jour auto**.
- Obtenir un certificat **OV/EV** (ou **Azure Trusted Signing**, moins cher et sans jeton matériel).
- electron-builder lit la signature via les variables d'environnement `CSC_LINK` (chemin/URL du .pfx) et `CSC_KEY_PASSWORD` : aucune modification de code requise une fois le certificat en place. Azure Trusted Signing demande en plus un bloc `win.azureSignOptions` dans `electron-builder.json` (à ajouter ce jour-là ; `test/installer/exe-identity.test.js` vérifie aujourd'hui qu'aucune signature n'est exigée et devra être adapté).
- `win.signAndEditExecutable` est déjà à `true` dans `electron-builder.json` : il pose aujourd'hui les informations de version de `RDVAULT.exe`, sans certificat ; sans `CSC_LINK`, la signature est simplement ignorée. Une fois le certificat fourni, le même réglage signera l'exécutable et l'installeur.

### 2. Activer les mises à jour automatiques
```bash
npm i electron-updater
```
- Ajuster `publish.owner`/`publish.repo` dans `electron-builder.json` (dépôt réel).
- Publier chaque release avec `electron-builder --publish always` (génère et téléverse `latest.yml` + l'installeur). Un jeton `GH_TOKEN` est nécessaire en CI.
- Le module `electron/autoUpdater.js` s'activera automatiquement une fois la dépendance présente et l'app empaquetée.
- Les mises à jour conservent déjà `config.cfg` et l'appairage de l'extension (voir « Installeur et mises à jour ») : une mise à jour automatique, silencieuse, ne réinitialisera pas la configuration des postes.

### 3. Publier l'extension sur les stores
- Chrome Web Store + Edge Add-ons : identifiant fixe, signature et mise à jour auto. Préalable au déploiement par GPO (stratégies de registre par navigateur, que l'installeur ne pose pas encore).
- Politique de confidentialité exigée par les stores : `PRIVACY.md` décrit les données traitées par les deux extensions ; la publier à une URL stable, la renseigner dans le tableau de bord du store et remplir l'onglet « Privacy practices » en cohérence (informations d'authentification, hôtes visités transmis à l'application locale).

### 4. Audit de sécurité externe
- Faire auditer le code et réaliser un test d'intrusion avant diffusion publique ; publier un résumé.

### 5. Juridique
- Faire valider `PRIVACY.md` et rédiger des CGU. Renseigner les adresses `security@` / `privacy@` réelles et une clé PGP.

## 🔜 Chantiers code recommandés (prochaines itérations)

- **Native Messaging** pour l'extension (supprime le port local `127.0.0.1`, fixe et partagé entre toutes les sessions Windows d'un poste : sur un poste multi-session, seule la première instance l'écoute, les autres n'affichent qu'un avertissement, au démarrage et après la connexion ; voir `SECURITY.md`).
- **Passkeys en mode Vault** : après une suppression, détruire les versions KV v2 antérieures du blob `.rdvault-passkeys` (elles contiennent les clés privées) ; le coffre local ne garde déjà que la dernière version. D'ici là, l'administrateur peut fixer `max_versions = 1` sur cette clé (`PASSKEYS.md`, « Stockage »).
- **Noms `.rdvault…` d'entrées utilisateur** (héritées de la 1.5.0 ou créées depuis l'éditeur) : réserver seulement les noms internes exacts (`.rdvault-passkeys`, `.rdvault-keycheck`) dans l'export, l'import, la lecture multi-coffres (`src/utils/readAllSecrets.js` : extension, recherche, audit) et la purge d'historique du coffre local (`isHiddenBlobKey`, `electron/localVault/secretsService.js`), comme le fait déjà le tableau (`isInternalSecretKey`, `src/utils/passkeyEngine.js`).
- **Migration KDF opt-in** des coffres PBKDF2 → scrypt lors d'un déverrouillage réussi (re-dériver et re-chiffrer l'enveloppe de clé).
- **Quitter react-scripts pour Vite** + TypeScript ; tenir Electron sur une version supportée.
- **Montée en charge** : lecture indexée / recherche côté serveur local, listes virtualisées. Le chargement lit toujours les secrets un par un, mais au plus 24 requêtes à la fois, avec signalement des entrées non lues ; listage plafonné à 20 000 entrées et 20 niveaux de dossiers par coffre (au-delà, liste partielle affichée avec un avertissement) ; au plus 100 000 entrées transmises à l'extension (avertissement au-delà). Le tableau rend encore toutes ses lignes (mémoïsées) : `content-visibility` ne s'applique pas aux lignes d'un `<table>` (mise en page de 5 000 lignes inchangée, environ 65 ms mesurées sous Chromium), il faudrait une liste virtualisée ou une mise en page hors `<table>`. L'IPC `sync-write-state` reçoit l'état complet à chaque écriture (environ 18 ms mesurées pour 5 000 entrées) : une API incrémentale n'a pas été jugée nécessaire à ce stade.
- **Multiplateforme** : macOS / Linux (stockage sécurisé, lanceurs, presse-papiers).
- **Synchronisation multi-appareils chiffrée de bout en bout** + récupération de compte sans porte dérobée.
- **IHM de mise à jour** complète dans les Paramètres (bouton « Vérifier / Installer maintenant ») — l'API preload `electronUpdater` est déjà prête.
- **Accessibilité (WCAG)** : audit complet par un tiers (clavier, focus des modales, rôles ARIA, contrastes et sens de lecture de droite à gauche déjà traités, panneau d'administration compris ; panneau d'administration et extensions traduits dans les 12 langues).
- **Vulnérabilités de dépendances** (`npm audit --omit=dev`, à relancer pour l'état courant) : au 2026-10-09, **après correction, 7 vulns hautes en prod, 0 modérée** (avant : 9, dont 8 hautes et 1 modérée), toutes dans la chaîne `puppeteer-core` 24.
  - ✅ **Corrigé** (même version majeure, `--ignore-scripts`) : `axios` 1.12.2 → **1.20.0** (dépendance directe, client HTTP du renderer ; plage `^1.20.0`), qui tire `follow-redirects` 1.16.1 et `form-data` 4.0.6 ; transitives montées dans leurs plages semver : `ws` 8.22.0 (CDP de `puppeteer-core`), `ip-address` 10.7.3 (via `socks`), `basic-ftp` 5.3.1 (corrige GHSA-rpmf-866q-6p89). axios 1.20 ajoute `https-proxy-agent` 5 / `agent-base` 6 aux dépendances de production. Revalidé : lint, tests React et Electron, tests de fumée (4 suites), build de production, e2e UI et e2e extension.
  - ⏳ **Restant (7 hautes, une seule chaîne)** : `puppeteer-core` → `@puppeteer/browsers` → `extract-zip` ≤ 2.0.1 (GHSA-jmr9-qjv8-65gv, GHSA-7pqw-9j4j-h8q3 : écriture hors dossier via lien symbolique à l'extraction d'une archive) et → `proxy-agent` → `pac-proxy-agent` → `get-uri` 6 → `basic-ftp` 5.3.1 (GHSA-c475-qrg2-pj4r : CPU quadratique dans `Client.list()` ; correctif seulement en `basic-ftp` 6.2.1, que `get-uri` 6 n'accepte pas). Aucune version 24.x ne corrige (24.43.1, dernière de la branche, embarque encore `@puppeteer/browsers` 2.13.2 / `extract-zip`) : `puppeteer-core` laissé en 24.42.0. **Exploitabilité faible dans RDVAULT** : ces chemins ne servent qu'à télécharger et installer un navigateur (`install()` de `@puppeteer/browsers`, fichier PAC en `ftp://`), alors que RDVAULT se contente de `puppeteer.launch()` sur un Chrome local (embarqué ou système) et n'appelle jamais ces fonctions (aucune référence dans `electron/`, `cli/`, `src/`). Correction complète : `puppeteer-core` 25 (version majeure), dans un lot dédié avec revalidation du RBI (`electron/secureSession.js`) et des e2e.
  - **Procédure de mise à jour** (environnement natif fragile) : `npm install <paquet>@<version> --ignore-scripts` (sinon `better-sqlite3`, compilé pour l'ABI Electron, risque d'être recompilé pour Node), vérifier ensuite que `node_modules/better-sqlite3/build/Release/better_sqlite3.node` est inchangé, et supprimer `node_modules/cpu-features` s'il réapparaît (dépendance optionnelle de `ssh2` qui casse l'empaquetage).
  - Le reste de `npm audit` (sans `--omit=dev`) provient des dépendances de développement (`react-scripts`/webpack, outillage de build), **non embarquées** dans l'app — argument supplémentaire pour la migration vers Vite.
  - L'étape d'audit de la CI reste non bloquante tant que ces vulnérabilités de production sont ouvertes.
