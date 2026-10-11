# mvault — CLI pour RDVault

Client en ligne de commande pour accéder aux secrets HashiCorp Vault via l'application desktop RDVault.

## Pré-requis

- **RDVault Desktop** doit être lancé et l'utilisateur connecté
- **Node.js** >= 16 (pour l'installation via npm)
- **OpenSSH** (`ssh`) pour `mvault ssh` en mode **clé** (Windows : fonctionnalité optionnelle « Client OpenSSH »,
  `C:\Windows\System32\OpenSSH\ssh.exe` ; override du binaire via `MVAULT_SSH_BIN`). Le mode **mot de passe**
  n'a besoin d'aucun client : RDVault se connecte lui-même.
- **PowerShell** pour `mvault winrm`
- **PuTTY** (plink) / **sshpass** uniquement pour la méthode manuelle (« en pilotant le client soi-même », plus bas)

## Installation

```bash
cd cli
npm link
```

La commande `mvault` est désormais disponible globalement.

## Commandes

```bash
mvault engines                              # Lister les coffres disponibles
mvault ls <engine>[/dossier]                # Lister les secrets d'un coffre
mvault get <engine>/<chemin>                # Récupérer un secret (JSON, valeurs sensibles masquées)
mvault get <engine>/<chemin> --reveal       # Récupérer un secret sans masquage
mvault get <engine>/<chemin> -k <clé>       # Récupérer un champ spécifique (texte brut)
mvault ssh <user@hôte> -s <e>/<p> [-p <port>] [--hostkey SHA256:…] [--exec-timeout <s>] [-- <cmd>]
                                            # Session SSH (clé → agent, ou mot de passe → broker avec -- <cmd>)
mvault winrm <user@hôte> -s <e>/<p> [-p <port>] -- <cmd>   # Commande Windows (WinRM), identifiant jamais exposé
mvault rules                                # Afficher les règles d'auto-approbation (lecture seule)
mvault status                               # Vérifier que RDVault est actif
```

Alias : `-s` = `--secret`, `-p` = `--port`, `-k` = `--key`.

Sans `-k` ni `--reveal`, les clés `password`, `pass`, `secret`, `token`, `key` et `private_key`
(insensible à la casse) sont affichées sous la forme `********`, pour éviter de laisser des mots de passe
dans l'historique du terminal. Les règles d'auto-approbation se modifient uniquement dans RDVault
(Paramètres > CLI).

## Connexion SSH avec mvault

### Recommandé — clé SSH jamais exposée (`mvault ssh`)

Pour une authentification **par clé**, `mvault ssh` est la méthode la plus sûre : RDVault charge la
clé privée du coffre dans un **agent SSH éphémère** (comme Pageant/1Password) et lance `ssh` en lui
pointant dessus via `SSH_AUTH_SOCK`. La clé **n'est jamais transmise** à l'appelant — ni en argument,
ni dans la sortie, ni dans une variable d'environnement. Elle est seulement *utilisée* pour signer le
défi d'authentification, sous confirmation (ou règle d'auto-approbation) et journalisée dans l'audit.

```bash
mvault ssh <user@hôte> --secret|-s <engine>/<chemin> [--key-field <champ>] [--port|-p <n>] [-- <args ssh>]

# Exemple : la clé privée stockée dans le coffre n'est jamais révélée
mvault ssh admin@192.168.20.50 --secret users/moi/LAB/cle-prod
mvault ssh deploy@srv -s secret/deploy -p 2222 -- -o StrictHostKeyChecking=accept-new
```

- `--secret` pointe vers un secret contenant une clé privée (PEM/OpenSSH). Sans `--key-field`, RDVault
  repère automatiquement le champ ressemblant à une clé (`-----BEGIN … PRIVATE KEY-----`).
- L'agent (et la clé qu'il détient en mémoire) est détruit dès la fin de la session `ssh` : `mvault`
  attend l'accusé de RDVault avant de quitter, y compris sur Ctrl+C (le signal est relayé à `ssh`, un second
  Ctrl+C force la sortie après destruction de l'agent). Un garde-fou le détruit de toute façon après 2 minutes.
- `ssh` doit être installé (OpenSSH). Override du binaire via `MVAULT_SSH_BIN`. En mode clé, la clé d'hôte
  est vérifiée par `ssh` lui-même (`~/.ssh/known_hosts`), pas par RDVault : `--hostkey` et `--exec-timeout`
  (options du broker mot de passe) ne s'appliquent pas, et `mvault` l'indique par un avertissement sur stderr.

### Mot de passe SSH sans l'exposer (broker intégré)

Si le secret contient un **mot de passe** (pas de clé), RDVAULT ouvre lui-même la connexion SSH avec le
mot de passe du coffre ; le mot de passe ne quitte jamais RDVAULT. Deux usages :

```bash
# Exécuter une commande et récupérer la sortie
mvault ssh admin@192.168.20.50 --secret users/moi/LAB/SRV-Viewer -- "hostname && uptime"

# Shell INTERACTIF (sans commande) : votre terminal est relayé sur la session, le mdp reste côté RDVAULT
mvault ssh admin@192.168.20.50 --secret users/moi/LAB/SRV-Viewer

# Empreinte de clé d'hôte épinglée et délai d'exécution de 30 s
mvault ssh admin@192.168.20.50 -s users/moi/LAB/SRV-Viewer --hostkey SHA256:/OOQ7jKa7ZKJIYcAV0fcVF3F6bm4f0F9Y5JR6Our0gk --exec-timeout 30 -- "uptime"
```

**Vérification de la clé d'hôte** (le mot de passe n'est jamais envoyé à un serveur dont la clé n'est pas
acceptée, la vérification ayant lieu pendant l'échange de clés, avant l'authentification) :

- `--hostkey SHA256:…` : empreinte **épinglée** ; si la clé du serveur diffère, la connexion est refusée
  (`HOST_KEY_MISMATCH`). L'empreinte s'obtient avec `ssh-keyscan` + `ssh-keygen -lf` (voir plus bas). Pour un
  `hôte:port` encore inconnu, l'empreinte épinglée est mémorisée dans `known_hosts.json` ; elle ne remplace
  **jamais** une autre clé déjà mémorisée : la connexion est alors refusée (`HOST_KEY_CHANGED`, voir ci-dessous).
- Sans `--hostkey` : mémoire persistante **TOFU** (*trust on first use*) dans `known_hosts.json` du dossier
  userData de RDVault (`%APPDATA%\RDVAULT\known_hosts.json` sur Windows, même dossier que `cli/session.json`),
  partagée avec l'audit SSH de l'application. À la **première connexion** à un `hôte:port`, RDVault affiche une
  popup « Clé d'hôte SSH inconnue — CLI mvault » avec l'empreinte : **Mémoriser et continuer** l'enregistre,
  **Refuser** (ou l'absence de réponse en 30 s) refuse la connexion (`HOST_KEY_REJECTED`). Cette décision n'est
  jamais auto-approuvée par les règles de chemin.
- Si la clé mémorisée **change**, la connexion est refusée (`HOST_KEY_CHANGED`) et `mvault` affiche un
  avertissement façon OpenSSH avec les empreintes attendue/observée et le chemin du fichier : supprimez
  l'entrée `hôte:port` de `known_hosts.json` seulement si le changement est légitime (serveur réinstallé).
- Après chaque connexion réussie, `mvault` rappelle sur **stderr** la clé vérifiée :
  `Clé d'hôte 192.168.20.50:22 : SHA256:… (nouvelle, mémorisée | connue | épinglée)`.
- Si le serveur présente une **autre** clé lors d'un renouvellement des clés (re-KEX) **en cours de session**,
  la connexion est interrompue (`HOST_KEY_CHANGED_REKEY`) : `mvault` affiche « la clé d'hôte a changé EN COURS
  de session : connexion interrompue ; known_hosts n'a pas été modifié ». La clé vérifiée à la connexion reste
  celle mémorisée : il n'y a **rien** à supprimer dans `known_hosts.json` ; ce comportement anormal est à signaler
  à l'administrateur du serveur. La session était authentifiée : la commande a pu s'exécuter en partie (sa sortie
  n'est pas affichée) ; un shell interactif est refermé, avec le même avertissement et le code de sortie `1`.
- Toutes les décisions sont journalisées dans `audit.log` (`SSH-HOSTKEY` : `new:`, `rejected`, `changed`,
  `changed-rekey`, `pinned:` / `pinned-new:` pour un épinglage, `client-parti` si `mvault` a abandonné pendant
  la popup).

`--exec-timeout <secondes>` borne la durée d'exécution de la commande (défaut 600, `0` = illimité, max 3600) ;
dépassement → `Délai d'exécution SSH dépassé`. Les méthodes `plink`/`sshpass` ci-dessous restent utilisables
si vous préférez piloter le client vous-même.

**Code de sortie** (commande via le broker, et `mvault winrm`) : celui de la commande distante ; `128 + n` si
elle a été tuée par un signal (ex. 137 pour `KILL`) ; `1` si aucun statut n'a été reçu (jamais `0` par défaut).

**Fin d'un shell interactif** : quand la socket se ferme, `mvault` demande à RDVault la raison de la fin
(`POST /ssh/status`) avant de quitter :

| Raison (`closedReason` / `code`) | Sortie de `mvault` |
|---|---|
| `closed` / `null` : shell quitté (`exit`), fermeture propre par le serveur distant | `0`, aucun message |
| `host-key-changed-rekey` / `HOST_KEY_CHANGED_REKEY` : clé d'hôte changée en cours de session | avertissement ci-dessus, `1` |
| `max-duration` / `SESSION_MAX_DURATION` : garde-fou de RDVault (session de plus de 4 h) | message, `1` |
| `closed-by-request` / `CLOSED_BY_REQUEST` : fermée par un autre client CLI (`/ssh/close`) | message, `1` |
| RDVault injoignable (application fermée, déconnexion, session CLI révoquée) | message, `1` |

L'état d'une session (`{ open, closedReason, code }`) reste consultable 5 minutes après sa fin, uniquement avec le
jeton qui l'a ouverte : une session inconnue, expirée ou ouverte avec un autre jeton reçoit le même `404`. La fin
de chaque shell est journalisée (`SSH-SHELL` … `shell-ferme:<raison>`). Une coupure réseau en cours de session
est pour l'instant rapportée comme une fin normale (le broker ne transmet que l'erreur de clé d'hôte).

**Erreurs du broker** (réponse de `POST /ssh` : `{ success: false, error: <code>, message }`, que `mvault` traduit
en message explicite) :

| Code | HTTP | Signification |
|---|---|---|
| `HOST_KEY_MISMATCH` | 502 | La clé du serveur ne correspond pas à `--hostkey` |
| `HOST_KEY_CHANGED` | 502 | La clé diffère de celle mémorisée (y compris avec un `--hostkey` contradictoire) |
| `HOST_KEY_REJECTED` | 403 | Clé inconnue refusée (popup refusée, expirée ou sans fenêtre) |
| `KNOWN_HOSTS_READ` | 500 | `known_hosts.json` illisible ou corrompu : corrigez ou supprimez-le (rien n'est réécrit) |
| `KNOWN_HOSTS_WRITE` | 500 | Mémorisation de la clé impossible (droits, disque plein) |
| `CONNECT_TIMEOUT` | 504 | Délai de connexion dépassé (20 s, hors temps de la popup de clé d'hôte) |
| `EXEC_TIMEOUT` | 504 | Délai d'exécution dépassé (`--exec-timeout`) : commande interrompue, connexion fermée |
| `HOST_KEY_CHANGED_REKEY` | 502 | Clé d'hôte changée lors d'un re-KEX **en cours de session** : connexion interrompue, `known_hosts.json` non modifié |

Pour les cinq premiers codes, le refus a lieu pendant l'échange de clés : le mot de passe n'est **pas** envoyé.
Si `mvault` abandonne la requête (délai HTTP dépassé, Ctrl+C) pendant une popup, RDVault n'ouvre ensuite ni
agent ni connexion pour ce client parti (journalisé `client-parti`) ; un shell établi après son départ est
refermé aussitôt au lieu de rester ouvert jusqu'au garde-fou de 4 h. S'il abandonne **pendant la connexion
SSH** (échange de clés, authentification) ou pendant l'exécution, RDVault détruit aussitôt la connexion : une
commande ou un shell qui n'était pas encore lancé ne l'est **jamais** (journalisé `SSH-EXEC` / `SSH-SHELL`
`client-parti`) ; une commande en cours est interrompue côté client (connexion coupée).

### Windows à distance — WinRM / PowerShell Remoting

```bash
mvault winrm <user@hôte> --secret|-s <engine>/<chemin> [--ssl] [--port|-p <n>] [--auth <méthode>] -- <commande PowerShell>

# Exemple : l'identifiant Windows n'est jamais exposé
mvault winrm administrateur@srv --secret users/moi/win/admin -- "hostname; whoami; Get-Service WinRM"
```

RDVAULT exécute `Invoke-Command` avec l'identifiant du coffre (mot de passe transmis à PowerShell par
**stdin**, jamais en argument) et ne renvoie que la sortie. Nécessite un listener WinRM configuré côté
serveur (`Enable-PSRemoting`) et PowerShell côté client. `--auth` : `Default`, `Negotiate`, `Kerberos`,
`Basic` ou `CredSSP` ; `--ssl` pour HTTPS (port 5986).

### Par mot de passe, en pilotant le client soi-même (plink / sshpass)

Le mot de passe ne doit **jamais** être passé en argument de ligne de commande (`plink -pw`, `sshpass -p`) :
les arguments sont visibles par tous les processus de la machine (`ps`, Gestionnaire des tâches) et peuvent
finir dans l'historique du shell. Utilisez un fichier temporaire (`plink -pwfile`) ou l'environnement
(`sshpass -e`).

### Étape 1 — Récupérer la clé hôte du serveur (obligatoire avec plink)

PuTTY (`plink`) exige de vérifier la clé hôte du serveur distant à chaque première connexion.
**Cette étape doit être répétée pour chaque nouveau serveur** auquel vous vous connectez.

```bash
# Scanner la clé publique du serveur
ssh-keyscan -t ed25519 <IP_DU_SERVEUR>

# Obtenir le fingerprint SHA256 utilisable par plink
ssh-keygen -lf <(echo "<SORTIE_DE_SSH-KEYSCAN>")
```

Exemple concret :

```bash
$ ssh-keyscan -t ed25519 192.168.20.50
192.168.20.50 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBjyz...

$ ssh-keygen -lf <(echo "192.168.20.50 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBjyz...")
256 SHA256:/OOQ7jKa7ZKJIYcAV0fcVF3F6bm4f0F9Y5JR6Our0gk 192.168.20.50 (ED25519)
```

Le fingerprint est `SHA256:/OOQ7jKa7ZKJIYcAV0fcVF3F6bm4f0F9Y5JR6Our0gk`.

### Étape 2 (Windows / PuTTY) — `plink -pwfile` avec fichier temporaire

Le mot de passe est écrit dans un fichier temporaire lisible uniquement par l'utilisateur courant,
utilisé par `plink -pwfile`, puis **supprimé** quoi qu'il arrive.

PowerShell :

```powershell
$pwfile = Join-Path $env:TEMP ("mvault-" + [guid]::NewGuid().ToString("N"))
try {
  # Fichier accessible uniquement par l'utilisateur courant
  New-Item -ItemType File -Path $pwfile -Force | Out-Null
  icacls $pwfile /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
  [IO.File]::WriteAllText($pwfile, (mvault get <engine>/<chemin> -k password))

  plink -batch -hostkey "SHA256:<FINGERPRINT>" -ssh -pwfile $pwfile <user>@<host> "<commande>"
} finally {
  Remove-Item -Force $pwfile -ErrorAction SilentlyContinue
}
```

Git Bash / WSL :

```bash
pwfile="$(mktemp)"
trap 'rm -f "$pwfile"' EXIT
mvault get <engine>/<chemin> -k password > "$pwfile"

plink -batch -hostkey "SHA256:<FINGERPRINT>" -ssh -pwfile "$pwfile" <user>@<host> "<commande>"
```

Exemple complet :

```bash
pwfile="$(mktemp)"
trap 'rm -f "$pwfile"' EXIT
mvault get users/rdekien/LAB-TEST/Serveur/SRV-Viewer -k password > "$pwfile"

plink -batch \
  -hostkey "SHA256:/OOQ7jKa7ZKJIYcAV0fcVF3F6bm4f0F9Y5JR6Our0gk" \
  -ssh -pwfile "$pwfile" \
  viewer@192.168.20.50 "hostname && uptime"
```

### Étape 2 (Linux / macOS) — `sshpass -e` avec la variable `SSHPASS`

`sshpass -e` lit le mot de passe dans la variable d'environnement `SSHPASS`, définie uniquement pour la
durée de la commande :

```bash
SSHPASS="$(mvault get <engine>/<chemin> -k password)" sshpass -e ssh <user>@<host> "<commande>"
```

Exemple complet :

```bash
SSHPASS="$(mvault get users/rdekien/LAB-TEST/Serveur/SRV-Viewer -k password)" \
  sshpass -e ssh viewer@192.168.20.50 "hostname && uptime"
```

### Pourquoi la clé hôte est nécessaire

- **Sécurité** : la clé hôte authentifie le serveur distant. Sans elle, un attaquant pourrait intercepter la connexion (man-in-the-middle).
- **plink en mode batch** : le flag `-batch` empêche toute interaction. Sans `-hostkey`, plink refuse de se connecter à un serveur inconnu.
- **Une seule fois par serveur** : une fois le fingerprint récupéré, il reste valide tant que le serveur ne change pas sa clé SSH.

### Astuce : stocker les fingerprints

Pour éviter de chercher le fingerprint à chaque fois, vous pouvez créer un fichier de référence :

```bash
# hostkeys.txt
# Format : IP  FINGERPRINT
192.168.20.30  SHA256:iyKx1upVWl++k5JmJ4D1M+gndxtKJB+0pMw3xh1FFP4
192.168.20.50  SHA256:/OOQ7jKa7ZKJIYcAV0fcVF3F6bm4f0F9Y5JR6Our0gk
```

## Permissions CLI (Paramètres > CLI)

L'onglet **CLI** dans les paramètres de RDVault permet de contrôler les accès par coffre :

| Permission | Description |
|---|---|
| **Listing** | Autorise `mvault ls` sur ce coffre (noms des secrets uniquement, pas les mots de passe) |
| **Auto-get** | Supprime la popup de confirmation d'accès sur ce coffre pour `mvault get`, **mais aussi** pour `mvault ssh` (agent ou broker mot de passe, commande ou shell) et `mvault winrm`, qui utilisent le secret pour se connecter et exécuter des commandes |

Par défaut, les deux sont désactivés. Chaque `mvault get`, `mvault ssh` ou `mvault winrm` déclenche une popup de
confirmation dans RDVault. Avec **Auto-get**, seule subsiste la popup de clé d'hôte SSH inconnue (première connexion
à un `hôte:port` sans `--hostkey`), qui n'est jamais auto-approuvée. Au-delà de 15 accès auto-approuvés par minute,
la popup est de nouveau exigée (détection de rafale).
Les règles ne sont modifiables que depuis l'application (`mvault rules` est en lecture seule).

## Architecture

```
mvault (CLI)
  │
  │  HTTP local (127.0.0.1, port dynamique)
  │  Token de session (généré à chaque démarrage)
  ▼
cliServer.js (serveur HTTP dans Electron)
  │
  │  IPC Electron
  ▼
App.jsx (React) ──► API Vault (HTTPS)
                         │
                         ▼
                    HashiCorp Vault
```

**Aucun mot de passe n'est stocké en local.** Les secrets transitent uniquement en mémoire.

## Fichiers

Le dossier correspond au `userData` Electron de l'application (`productName` = `RDVAULT`).

| Plateforme | Fichier de session |
|---|---|
| Windows | `%APPDATA%\RDVAULT\cli\session.json` |
| Linux | `~/.config/RDVAULT/cli/session.json` (ou `$XDG_CONFIG_HOME/RDVAULT/cli/session.json`) |
| macOS | `~/Library/Application Support/RDVAULT/cli/session.json` |

Le fichier contient le port et le token de session ; il est supprimé à la fermeture de RDVault.
Le journal d'audit `audit.log` et sa clé `audit-key` sont dans le même dossier `cli/` (voir ci-dessous). Les
clés d'hôte SSH mémorisées sont dans `known_hosts.json` à la racine du dossier userData
(`%APPDATA%\RDVAULT\known_hosts.json` sur Windows).

### Journal d'audit (`cli/audit.log`)

Une ligne par accès : `date | action | chemin | APPROVED/DENIED | détail` (chemins + approbations, décisions
de clé d'hôte `SSH-HOSTKEY`, départs du client `client-parti`, ouverture et fin des shells `shell-ouvert` /
`shell-ferme:<raison>`). Les caractères de contrôle (retours ligne, séquences ANSI) y sont neutralisés en `?`.

Les commandes SSH/WinRM ne sont **jamais** journalisées en clair (leurs arguments peuvent contenir des secrets) :
seule une référence `cmd:<exécutable>#<empreinte>` est écrite, par exemple `cmd:hostname#75116c53a4ac`. Une
affectation en tête comme `PGPASSWORD=… psql` devient `cmd:PGPASSWORD=***#<empreinte>`.

- L'empreinte est un **HMAC-SHA256 tronqué** (12 caractères hexadécimaux) de la commande complète, calculé avec
  une clé aléatoire de 32 octets **propre à l'installation**, créée à la première commande dans `cli/audit-key`
  (écriture atomique, droits `0600` sur Linux/macOS ; sous Windows, protégée par les ACL du profil utilisateur).
  Cette clé n'est jamais journalisée.
- L'empreinte permet de **corréler** deux commandes identiques sur la même installation (même empreinte), mais
  **pas de retrouver la commande hors-ligne** à partir du journal seul : sans la clé, un dictionnaire de
  commandes probables ne peut pas être testé (ce que permettait l'ancien SHA-256 non salé). Les empreintes ne
  sont pas comparables d'une installation à l'autre.
- Si la clé ne peut être ni lue ni créée (fichier illisible, taille inattendue, disque en lecture seule), la
  référence devient `cmd:<exécutable>#?` — jamais un hash non salé — et l'erreur est signalée dans le journal de
  l'application. Un fichier `audit-key` existant mais invalide n'est jamais écrasé : supprimez-le pour qu'une
  nouvelle clé soit créée (les empreintes antérieures ne seront alors plus corrélables aux nouvelles).

Compatibilité : si le fichier n'existe pas au nouveau chemin, `mvault` cherche l'ancien emplacement
(`rdvault/cli/session.json`). La variable `MVAULT_SESSION_FILE` permet d'imposer un chemin personnalisé.
