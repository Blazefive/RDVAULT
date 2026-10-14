# Politique de confidentialité — RDVAULT

*Dernière mise à jour : 2026-10-13. À valider par un juriste avant publication.*

RDVAULT est une application de bureau, accompagnée de deux extensions de navigateur (Chrome, Edge, Brave) : l'extension **enrichie** (« RDVAULT »), livrée avec l'installeur et reliée à l'application, et l'extension **simple** (« RDVAULT (Vault direct) »), reliée directement à un serveur HashiCorp Vault. Par conception, **vos secrets restent sur votre appareil** (mode local) ou sur le serveur HashiCorp Vault que **vous** contrôlez (mode entreprise).

## Ce que RDVAULT ne fait pas

- ❌ Aucune télémétrie, aucun pistage, aucune analytique tierce intégrée par défaut, ni dans l'application ni dans les extensions.
- ❌ Aucun envoi de vos secrets, mots de passe, noms d'utilisateur, URL ou sites visités à l'éditeur ou à un tiers.
- ❌ Aucun compte en ligne obligatoire.
- ❌ Aucun code chargé à distance par les extensions : tout leur code est dans le paquet installé.

## Données traitées et où elles vont

| Donnée | Emplacement | Transmission externe |
|--------|-------------|----------------------|
| Secrets, mots de passe, TOTP, passkeys | Coffre chiffré local (SQLite) **ou** votre serveur Vault | Aucune vers l'éditeur |
| Mot de passe maître | Jamais stocké (sert à dériver la clé en mémoire) | Jamais |
| État servi à l'extension enrichie | Mémoire de l'application uniquement, vidé à la déconnexion | Jamais (boucle locale `127.0.0.1`) |
| Préférences (thème, langue, colonnes), identifiant de connexion mémorisé, tags | Profil de l'application (`localStorage`) / fichier de config local | Jamais |
| Journal d'audit de la CLI `mvault` | `%APPDATA%\RDVAULT\cli\audit.log` (voir ci-dessous) | Jamais |
| Journaux techniques | Sortie console du processus, niveau `warn`/`error` en production, URL expurgées des query strings ; aucun fichier journal | Jamais |

## Extensions de navigateur

Les deux extensions ne demandent que les autorisations `storage` et `alarms`, plus l'accès réseau décrit ci-dessous. Elles n'écrivent rien dans `chrome.storage.local` et rien n'est synchronisé avec le compte du navigateur : ce qu'elles conservent est dans `chrome.storage.session` ou dans la mémoire de leur service worker, effacés à la fermeture du navigateur.

### Extension enrichie (reliée à l'application RDVAULT)

- **Seule destination réseau** : l'application RDVAULT du même appareil, `http://127.0.0.1:45678` (boucle locale). C'est sa seule autorisation d'hôte ; aucune donnée ne quitte l'appareil par l'extension.
- **Appairage** : à la première connexion, l'application affiche l'identifiant de l'extension et demande votre accord. L'identifiant approuvé est mémorisé par l'application dans `%APPDATA%\RDVAULT\paired-extensions.json`.
- **Données traitées** :
  - le nom d'hôte (sans chemin ni paramètres) de chaque page ou frame `https` qui contient un champ de connexion, envoyé à l'application pour trouver les entrées correspondantes ;
  - en réponse, le nom et l'identifiant des entrées correspondantes. Le mot de passe d'une entrée n'est demandé que lorsque vous la choisissez ; il est saisi dans le formulaire sans être conservé par l'extension ;
  - les codes TOTP de l'entrée choisie, pour remplir le champ de code ;
  - passkeys : à la création, la passkey générée (clé privée, identifiant du site `rpId`, nom d'utilisateur, origine) est transmise à l'application, qui l'enregistre dans votre coffre ; à la connexion, les passkeys du site sont lues dans le coffre. La clé privée n'est jamais exposée à la page.
- **Conservé dans le navigateur** (`chrome.storage.session`) : le jeton de session qui relie l'extension à l'application ; pendant 5 minutes au plus, le dernier identifiant choisi (nom de l'entrée, coffre, nom de la clé TOTP, hôte, **jamais le mot de passe**), pour proposer le code TOTP sur la page suivante.

### Extension simple (reliée directement à un serveur Vault)

- **Seule destination réseau** : le serveur Vault dont vous saisissez l'adresse (`https://` obligatoire). L'identifiant et le mot de passe LDAP saisis dans la fenêtre de l'extension lui sont envoyés pour ouvrir une session.
- **Conservé dans le navigateur** : adresse du serveur, espace de noms, jeton Vault et nom d'utilisateur dans `chrome.storage.session` ; les secrets lisibles avec ce jeton, mots de passe compris, dans la mémoire du service worker pendant 5 minutes au plus, pour proposer les entrées du site. La déconnexion efface tout.
- L'autorisation d'accès à tous les sites `https` sert à détecter les formulaires de connexion et à joindre le serveur Vault configuré ; les pages visitées ne sont transmises à personne.

## Connexions réseau sortantes de l'application (toutes optionnelles ou contrôlées par vous)

- **Serveur Vault** : uniquement en mode entreprise, vers l'URL que vous configurez.
- **Vérification de fuite (Have I Been Pwned)** : **uniquement** quand vous cliquez sur « Vérifier les fuites ».
  Transmission en **k-anonymity** : seuls les 5 premiers caractères du SHA-1 d'un mot de passe sont envoyés à `api.pwnedpasswords.com`. Le mot de passe en clair ne quitte jamais l'appareil, et le service ne peut pas savoir lequel vous testez.
- **Connexions que vous lancez vous-même** (SSH ou WinRM via `mvault`, lecture des journaux d'audit Vault par SSH, navigation isolée RBI et son proxy, lanceurs SSH/RDP/SFTP) : uniquement vers les hôtes que vous indiquez ou configurez.
- **Mise à jour automatique** : une fois `electron-updater` activé (voir `docs/PRODUCTION-READINESS.md`), l'application vérifiera la présence d'une nouvelle version auprès du dépôt de distribution, sans transmettre de donnée personnelle. **Dans la version actuelle, aucune requête de mise à jour n'est émise** (le module n'est pas installé).

## Données locales et suppression complète

Dans le profil de chaque utilisateur Windows, RDVAULT écrit dans `%APPDATA%\RDVAULT\` :

- `local-vault.db`, avec ses fichiers `local-vault.db-wal` et `local-vault.db-shm` : coffre local chiffré (mode local) ;
- `cli\audit.log` : journal des accès de la CLI `mvault` (date, action, chemin du secret, décision, `utilisateur@hôte` des connexions SSH et WinRM ; jamais la valeur d'un secret), `cli\audit-key` (clé propre à l'installation) et `cli\session.json` (jeton de la session CLI en cours) ;
- `known_hosts.json` : clés des hôtes SSH approuvés, donc la liste des hôtes contactés ;
- `paired-extensions.json` : identifiants des extensions approuvées ;
- `config.cfg` / `config.json` éventuels ;
- le profil de l'interface (dossiers `Local Storage`, `Session Storage` et caches de Chromium) : préférences, identifiant de connexion mémorisé, tags, règles d'auto-approbation de la CLI, hôtes et utilisateurs SSH de l'audit du panneau d'administration.

S'y ajoutent, hors du profil : la configuration de l'installation (`config.cfg` dans le dossier d'installation, et `%PROGRAMDATA%\RDVAULT\` pour un déploiement d'entreprise), les fichiers que vous exportez à l'emplacement choisi, et des fichiers temporaires dans `%TEMP%` (profils des sessions RBI `rbi-*`, fichiers de lancement RDP et SFTP), supprimés automatiquement.

La désinstallation retire `config.cfg`, la session CLI et l'appairage des extensions de l'utilisateur qui désinstalle, ainsi que les profils RBI temporaires. Elle **conserve** le coffre local, le journal d'audit de la CLI, `known_hosts.json` et le profil de l'interface. **Pour supprimer toutes les données locales**, désinstallez l'application, supprimez le dossier `%APPDATA%\RDVAULT` en entier dans le profil de chaque utilisateur qui s'en est servi, puis `%PROGRAMDATA%\RDVAULT` s'il existe, et retirez les extensions du navigateur (ce qui efface leur stockage). En mode entreprise, vos secrets restent sur votre serveur Vault, sous la responsabilité de son administrateur.

## Vos droits (RGPD)

Les données étant stockées localement et sous votre contrôle, l'éditeur n'est pas destinataire de vos données personnelles. Vous pouvez supprimer l'intégralité des données locales en suivant la section « Données locales et suppression complète » ci-dessus.

## Contact

Questions relatives à la confidentialité : `privacy@rdvault.example` *(à remplacer avant publication)*.
