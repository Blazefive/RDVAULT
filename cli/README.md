# mvault — CLI pour RDVault

Client en ligne de commande pour accéder aux secrets HashiCorp Vault via l'application desktop RDVault.

## Pré-requis

- **RDVault Desktop** doit être lancé et l'utilisateur connecté
- **Node.js** >= 16 (pour l'installation via npm)
- **PuTTY** (plink) pour les connexions SSH sur Windows

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
mvault get <engine>/<chemin>                # Récupérer un secret (JSON)
mvault get <engine>/<chemin> -k <clé>       # Récupérer un champ spécifique (texte brut)
mvault rules                                # Afficher les règles d'auto-approbation
mvault status                               # Vérifier que RDVault est actif
```

## Connexion SSH avec mvault

### Étape 1 — Récupérer la clé hôte du serveur (obligatoire)

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

### Étape 2 — Se connecter avec les credentials du vault

```bash
plink -batch -hostkey "SHA256:<FINGERPRINT>" -ssh \
  -pw "$(mvault get <engine>/<chemin> -k password)" \
  <user>@<host> "<commande>"
```

Exemple complet :

```bash
plink -batch \
  -hostkey "SHA256:/OOQ7jKa7ZKJIYcAV0fcVF3F6bm4f0F9Y5JR6Our0gk" \
  -ssh \
  -pw "$(mvault get users/rdekien/LAB-TEST/Serveur/SRV-Viewer -k password)" \
  viewer@192.168.20.50 "hostname && uptime"
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
| **Auto-get** | Supprime la popup de confirmation pour `mvault get` sur ce coffre |

Par défaut, les deux sont désactivés. Chaque `mvault get` déclenche une popup de confirmation dans RDVault.

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

| Fichier | Contenu |
|---|---|
| `%APPDATA%/rdvault/cli/session.json` | Port + token de session (supprimé à la fermeture) |
| `%APPDATA%/rdvault/cli/audit.log` | Journal des accès CLI (chemins + approbations) |
