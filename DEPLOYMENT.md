# RDVAULT — Guide de déploiement serveur (mode Enterprise)

Ce guide permet de reproduire l'infrastructure serveur nécessaire au fonctionnement de RDVAULT en mode Enterprise, depuis une machine Linux vierge.

## Architecture

```
┌──────────────────────────────────────────┐
│         Serveur Linux (Ubuntu 24.04)     │
│                                          │
│  ┌──────────────────────────────────┐    │
│  │  HashiCorp Vault (port 8200/TLS) │    │
│  │  Stockage : Raft intégré         │    │
│  │  Auth : LDAP                      │    │
│  │  Secrets : KV v2, PKI, TOTP      │    │
│  └──────────────────────────────────┘    │
│                                          │
│  ┌──────────────────────────────────┐    │
│  │  RBI Proxy (port 3001)           │    │
│  │  Node.js - wrapping/unwrapping   │    │
│  │  pour partage de sessions RBI    │    │
│  └──────────────────────────────────┘    │
│                                          │
│  SSH (port 22)                           │
└──────────────────────────────────────────┘
```

## Pré-requis

- Ubuntu 24.04 LTS (ou Debian 12+)
- 4 CPU, 8 Go RAM, 30 Go disque minimum
- Accès réseau depuis les postes clients sur les ports 8200 (HTTPS) et 3001 (HTTP)
- Un serveur LDAP (Active Directory ou OpenLDAP) pour l'authentification
- Un nom DNS pointant vers le serveur (ex: `vault.example.com`)

---

## Étape 1 — Installation de Vault

### Télécharger le binaire

```bash
# Version utilisée : 1.20.2 (vérifier la dernière version sur releases.hashicorp.com)
VAULT_VERSION="1.20.2"
wget https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip
unzip vault_${VAULT_VERSION}_linux_amd64.zip
sudo mv vault /usr/local/bin/
sudo chmod +x /usr/local/bin/vault
vault version
```

### Créer l'utilisateur système

```bash
sudo useradd --system --home /opt/vault --shell /bin/false vault
sudo mkdir -p /opt/vault/data
sudo mkdir -p /etc/vault.d
sudo mkdir -p /etc/vault-ssl
sudo chown -R vault:vault /opt/vault
sudo chown -R vault:vault /etc/vault.d
```

---

## Étape 2 — Certificats TLS

Vault écoute en HTTPS. Vous avez besoin d'un certificat pour votre nom DNS.

### Option A : Certificat auto-signé (lab/test)

```bash
# Générer une CA racine
openssl genrsa -out /etc/vault-ssl/ca.key 2048
openssl req -x509 -new -nodes -key /etc/vault-ssl/ca.key \
  -sha256 -days 3650 -out /etc/vault-ssl/ca.pem \
  -subj "/CN=Vault Root CA"

# Générer le certificat serveur
openssl genrsa -out /etc/vault-ssl/vault.key 2048
openssl req -new -key /etc/vault-ssl/vault.key \
  -out /etc/vault-ssl/vault.csr \
  -subj "/CN=vault.example.com"

# Signer avec la CA (SAN obligatoire)
cat > /tmp/vault-ext.cnf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:vault.example.com
EOF

openssl x509 -req -in /etc/vault-ssl/vault.csr \
  -CA /etc/vault-ssl/ca.pem -CAkey /etc/vault-ssl/ca.key \
  -CAcreateserial -out /etc/vault-ssl/vault.crt \
  -days 365 -sha256 -extfile /tmp/vault-ext.cnf

# Permissions
sudo chown vault:vault /etc/vault-ssl/vault.crt /etc/vault-ssl/vault.key /etc/vault-ssl/ca.pem
sudo chmod 600 /etc/vault-ssl/vault.key
sudo chmod 644 /etc/vault-ssl/vault.crt /etc/vault-ssl/ca.pem
```

### Option B : Certificat Let's Encrypt (production)

```bash
sudo apt install certbot
sudo certbot certonly --standalone -d vault.example.com
# Copier les certs dans /etc/vault-ssl/ et configurer un cron de renouvellement
```

> **Important** : Le certificat actuel de l'infra originale est **expiré** (valide jusqu'au 13/12/2025). RDVAULT continue de fonctionner car il accepte les certificats de domaines de confiance via `TRUSTED_DOMAINS` dans la config client. En production, maintenez vos certificats à jour.

---

## Étape 3 — Configuration de Vault

### /etc/vault.d/vault.hcl

```hcl
# Configuration Vault
disable_mlock = true
ui = true

# Adresses API et Cluster — remplacer par votre DNS
api_addr     = "https://vault.example.com:8200"
cluster_addr = "https://<IP_SERVEUR>:8201"

# Stockage Raft (intégré, pas besoin de Consul)
storage "raft" {
  path    = "/opt/vault/data"
  node_id = "vault-node1"
  performance_multiplier = 1
}

# Listener HTTPS
listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"

  # Taille max upload (100 MB, pour les pièces jointes)
  max_request_size = 104857600

  tls_disable     = 0
  tls_cert_file   = "/etc/vault-ssl/vault.crt"
  tls_key_file    = "/etc/vault-ssl/vault.key"
  tls_min_version = "tls12"
  tls_require_and_verify_client_cert = false
}

# Telemetry (optionnel)
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
}

# Niveau de log (info en production, trace pour debug)
log_level = "info"
```

```bash
sudo chown vault:vault /etc/vault.d/vault.hcl
sudo chmod 640 /etc/vault.d/vault.hcl
```

### /etc/hosts

Ajouter le nom DNS local :

```
<IP_SERVEUR> vault.example.com
```

---

## Étape 4 — Service systemd

### /etc/systemd/system/vault.service

```ini
[Unit]
Description=HashiCorp Vault
Documentation=https://www.vaultproject.io/docs/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/vault.d/vault.hcl

[Service]
Type=notify
User=vault
Group=vault
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
SecureBits=keep-caps
AmbientCapabilities=CAP_IPC_LOCK
CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
NoNewPrivileges=yes
ExecStart=/usr/local/bin/vault server -config=/etc/vault.d/vault.hcl
ExecReload=/bin/kill --signal HUP $MAINPID
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=65536
LimitMEMLOCK=infinity
Environment=VAULT_DISABLE_MLOCK=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable vault
sudo systemctl start vault
```

---

## Étape 5 — Initialisation de Vault

À faire **une seule fois** après la première installation :

```bash
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_CACERT="/etc/vault-ssl/ca.pem"

# Initialiser (génère les clés unseal et le root token)
vault operator init -key-shares=5 -key-threshold=3

# IMPORTANT : Sauvegarder les 5 clés unseal et le root token dans un endroit sûr !
# Exemple de sortie :
# Unseal Key 1: s0f29Qll...
# Unseal Key 2: PbEqwxxF...
# Unseal Key 3: gm8MOJ2A...
# Unseal Key 4: aVHWlqPL...
# Unseal Key 5: D2PG54+k...
# Root Token: hvs.xxxxxxxxxxxx

# Désceller (3 clés sur 5 nécessaires)
vault operator unseal <KEY_1>
vault operator unseal <KEY_2>
vault operator unseal <KEY_3>

vault status
```

> **Note** : Après chaque redémarrage du serveur, Vault est scellé. Il faut fournir 3 clés unseal pour le rendre opérationnel.

---

## Étape 6 — Configuration de l'authentification LDAP

```bash
export VAULT_TOKEN="<ROOT_TOKEN>"

# Activer LDAP
vault auth enable ldap

# Configurer la connexion LDAP (adapter à votre AD/LDAP)
vault write auth/ldap/config \
  url="ldap://votre-serveur-ad:389" \
  userattr="sAMAccountName" \
  userdn="OU=Users,DC=example,DC=com" \
  groupdn="OU=Groups,DC=example,DC=com" \
  groupfilter="(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))" \
  groupattr="cn" \
  binddn="CN=vault-bind,OU=ServiceAccounts,DC=example,DC=com" \
  bindpass="<MOT_DE_PASSE_BIND>" \
  insecure_tls=false \
  starttls=true
```

---

## Étape 7 — Engines secrets

### Engines à créer

```bash
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_SKIP_VERIFY=true
export VAULT_TOKEN="<ROOT_TOKEN>"

# Engines partagés (KV v2)
vault secrets enable -path=MonEquipe -version=2 kv
vault secrets enable -path=Stagiaires -version=2 kv

# Engine TOTP (un seul, global, les clés sont préfixées par engine)
vault secrets enable -path=TOTP totp

# Engine tags partagés (utilisé par RDVAULT pour les tags cross-users)
vault secrets enable -path=tags-shared -version=2 kv

# Engine PKI (optionnel, pour la gestion de certificats auto-signés)
vault secrets enable pki
```

> **Note** : Les engines personnels (`users/<username>/<nom>`) sont créés par les utilisateurs eux-mêmes via l'UI RDVAULT grâce à la policy self-service.

---

## Étape 7b — Modèle de droits RDVAULT

### Comprendre le modèle

RDVAULT utilise 5 niveaux de droits, chacun mappé à une policy Vault et un groupe AD :

```
┌─────────────────────────────────────────────────────────────┐
│                    MODÈLE DE DROITS                         │
├──────────────┬──────────────────────────────────────────────┤
│ Niveau       │ Ce que l'utilisateur peut faire              │
├──────────────┼──────────────────────────────────────────────┤
│ Admin        │ Tout. Gère les policies, engines, groupes,   │
│              │ audit. A la policy Vault "admin".            │
├──────────────┼──────────────────────────────────────────────┤
│ Modérateur   │ RW sur les coffres assignés + peut gérer     │
│              │ les policies, engines et groupes AD.          │
│              │ Ne voit pas les coffres des autres.           │
├──────────────┼──────────────────────────────────────────────┤
│ RW (écriture)│ Lecture + écriture sur un coffre spécifique. │
│              │ Peut créer/modifier/supprimer des secrets.    │
├──────────────┼──────────────────────────────────────────────┤
│ RO (lecture)  │ Lecture seule sur un coffre. Voit les secrets│
│              │ mais ne peut pas les modifier. Marqué "RO?"  │
│              │ dans l'UI RDVAULT.                           │
├──────────────┼──────────────────────────────────────────────┤
│ Self-service │ Chaque utilisateur peut créer/gérer ses      │
│              │ propres coffres sous users/<username>/.       │
│              │ Aucun accès aux coffres des autres.           │
└──────────────┴──────────────────────────────────────────────┘
```

### Comment ça fonctionne

1. L'utilisateur se connecte via LDAP (Active Directory)
2. Vault vérifie ses groupes AD
3. Chaque groupe AD est mappé à une ou plusieurs policies Vault
4. Les policies définissent les chemins accessibles et les capabilities
5. RDVAULT détecte automatiquement les droits via `sys/capabilities-self`

### Flux : donner accès à un coffre depuis l'AD

```
Groupe AD "equipe-compta"
        │
        ▼ (mapping dans Vault)
vault write auth/ldap/groups/equipe-compta policies="default,compta-rw"
        │
        ▼ (la policy compta-rw donne accès au coffre Comptabilite)
path "Comptabilite/data/*" { capabilities = ["create","read","update","delete","list"] }
        │
        ▼ (l'utilisateur voit le coffre dans RDVAULT)
```

---

## Étape 7c — Policies

### Policy `admin` — Accès complet

```bash
vault policy write admin - <<'EOF'
# Accès administrateur complet sur Vault
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
EOF
```

### Policy `self-service-ldap` — Coffres personnels

> **Important** : Remplacez `auth_ldap_XXXXXXXX` par l'accessor de votre auth LDAP. Pour le trouver : `vault auth list -format=json | jq -r '.["ldap/"].accessor'`

```bash
LDAP_ACCESSOR=$(vault auth list -format=json | jq -r '.["ldap/"].accessor')

vault policy write self-service-ldap - <<EOF
# Lister les coffres (nécessaire pour l'UI)
path "sys/mounts"   { capabilities = ["read","list"] }
path "sys/mounts/*" { capabilities = ["read","list"] }

# Créer / supprimer ses propres coffres sous users/<username>/
path "sys/mounts/users/{{identity.entity.aliases.${LDAP_ACCESSOR}.name}}"        { capabilities = ["create","update","delete","sudo"] }
path "sys/mounts/users/{{identity.entity.aliases.${LDAP_ACCESSOR}.name}}/*"      { capabilities = ["create","update","delete","sudo"] }
path "sys/mounts/users/{{identity.entity.aliases.${LDAP_ACCESSOR}.name}}/tune"   { capabilities = ["update","sudo"] }
path "sys/mounts/users/{{identity.entity.aliases.${LDAP_ACCESSOR}.name}}/*/tune" { capabilities = ["update","sudo"] }

# Pleins droits sur le contenu de ses coffres
path "users/{{identity.entity.aliases.${LDAP_ACCESSOR}.name}}/*" {
  capabilities = ["create","update","read","delete","list","patch"]
}

# TOTP : gestion complète
path "TOTP/keys/*" { capabilities = ["create","update","read","delete","list"] }
path "TOTP/code/*" { capabilities = ["create","read","update"] }
EOF
```

### Policy RW — Lecture/écriture sur un coffre

Template pour donner accès RW à un coffre nommé `MonCoffre` :

```bash
vault policy write moncoffre-rw - <<'EOF'
# Lister les coffres
path "sys/mounts"   { capabilities = ["read","list"] }
path "sys/mounts/*" { capabilities = ["read","list"] }

# KV v2 : accès complet au coffre MonCoffre
path "MonCoffre/metadata/*" { capabilities = ["list","read","delete"] }
path "MonCoffre/data/*"     { capabilities = ["create","update","read","delete","list"] }
path "MonCoffre/delete/*"   { capabilities = ["update"] }
path "MonCoffre/undelete/*" { capabilities = ["update"] }
path "MonCoffre/destroy/*"  { capabilities = ["update"] }

# TOTP préfixé par le nom du coffre en majuscules
path "TOTP/keys/MONCOFFRE-*"     { capabilities = ["create","update","read","delete"] }
path "TOTP/code/MONCOFFRE-*"     { capabilities = ["read"] }
path "TOTP/validate/MONCOFFRE-*" { capabilities = ["update"] }
EOF
```

### Policy RO — Lecture seule sur un coffre

```bash
vault policy write moncoffre-ro - <<'EOF'
# Lister les coffres
path "sys/mounts"   { capabilities = ["read","list"] }
path "sys/mounts/*" { capabilities = ["read","list"] }

# KV v2 : lecture seule
path "MonCoffre/metadata/*" { capabilities = ["list","read"] }
path "MonCoffre/data/*"     { capabilities = ["read"] }

# TOTP : lecture des codes uniquement
path "TOTP/code/MONCOFFRE-*"     { capabilities = ["read"] }
path "TOTP/validate/MONCOFFRE-*" { capabilities = ["update"] }
EOF
```

### Policy Modérateur — RW + gestion policies/engines/groupes

```bash
vault policy write moderateur - <<'EOF'
# Lister les coffres
path "sys/mounts"   { capabilities = ["read","list"] }
path "sys/mounts/*" { capabilities = ["read","list"] }

# KV v2 : accès complet aux coffres gérés
# MODERATOR: MonCoffre
path "MonCoffre/metadata/*" { capabilities = ["list","read","delete"] }
path "MonCoffre/data/*"     { capabilities = ["create","update","read","delete","list"] }
path "MonCoffre/delete/*"   { capabilities = ["update"] }
path "MonCoffre/undelete/*" { capabilities = ["update"] }
path "MonCoffre/destroy/*"  { capabilities = ["update"] }
path "TOTP/keys/MONCOFFRE-*"     { capabilities = ["create","update","read","delete"] }
path "TOTP/code/MONCOFFRE-*"     { capabilities = ["read"] }
path "TOTP/validate/MONCOFFRE-*" { capabilities = ["update"] }

# Permissions modérateur : gestion policies, mounts, groupes AD
path "sys/policies/acl"     { capabilities = ["list"] }
path "sys/policies/acl/*"   { capabilities = ["read","create","update"] }
path "sys/mounts"           { capabilities = ["read","list"] }
path "sys/mounts/*"         { capabilities = ["read","create","update","delete"] }
path "auth/ldap/groups"     { capabilities = ["list"] }
path "auth/ldap/groups/*"   { capabilities = ["read","create","update"] }

# Accès au coffre des tags partagés
path "tags-shared/metadata/*" { capabilities = ["list","read"] }
path "tags-shared/data/*"     { capabilities = ["create","update","read","list"] }
EOF
```

> **Note** : RDVAULT détecte automatiquement le rôle modérateur via le commentaire `# MODERATOR:` dans la policy. Ajoutez `# MODERATOR: NomCoffre` pour chaque coffre géré par le modérateur.

---

## Étape 7d — Groupes AD ↔ Policies

Le mapping se fait avec `vault write auth/ldap/groups/<nom-groupe-AD>`. Chaque groupe AD peut avoir plusieurs policies.

```bash
# Administrateurs — accès total
vault write auth/ldap/groups/admin-vault policies="admin"

# Utilisateurs standard — self-service (coffres personnels)
vault write auth/ldap/groups/self-service policies="default,self-service-ldap"

# Équipe Compta — accès RW au coffre Comptabilite
vault write auth/ldap/groups/equipe-compta policies="default,compta-rw"

# Stagiaires — accès RO au coffre Stagiaires
vault write auth/ldap/groups/stagiaires-ro policies="default,stagiaires-ro"

# Modérateurs — gestion des coffres et policies
vault write auth/ldap/groups/moderateurs policies="default,moderateur"
```

### Donner accès à un nouveau coffre : procédure complète

```bash
# 1. Créer l'engine KV v2
vault secrets enable -path=NouveauCoffre -version=2 kv

# 2. Créer la policy RW
vault policy write nouveaucoffre-rw - <<'EOF'
path "sys/mounts"   { capabilities = ["read","list"] }
path "sys/mounts/*" { capabilities = ["read","list"] }
path "NouveauCoffre/metadata/*" { capabilities = ["list","read","delete"] }
path "NouveauCoffre/data/*"     { capabilities = ["create","update","read","delete","list"] }
path "NouveauCoffre/delete/*"   { capabilities = ["update"] }
path "NouveauCoffre/undelete/*" { capabilities = ["update"] }
path "NouveauCoffre/destroy/*"  { capabilities = ["update"] }
path "TOTP/keys/NOUVEAUCOFFRE-*"     { capabilities = ["create","update","read","delete"] }
path "TOTP/code/NOUVEAUCOFFRE-*"     { capabilities = ["read"] }
path "TOTP/validate/NOUVEAUCOFFRE-*" { capabilities = ["update"] }
EOF

# 3. Créer le groupe AD dans Vault et associer la policy
vault write auth/ldap/groups/equipe-nouveau policies="default,self-service-ldap,nouveaucoffre-rw"

# 4. Dans l'AD, ajouter les utilisateurs au groupe "equipe-nouveau"
# → Ils verront automatiquement le coffre NouveauCoffre dans RDVAULT
```

### Retirer l'accès

```bash
# Retirer une policy d'un groupe
vault write auth/ldap/groups/equipe-nouveau policies="default,self-service-ldap"
# (la policy nouveaucoffre-rw n'est plus dans la liste)

# Ou supprimer le mapping du groupe entier
vault delete auth/ldap/groups/equipe-nouveau
```

---

## Étape 8 — RBI Proxy (optionnel)

Le proxy RBI permet le partage de sessions navigateur sécurisées. Il fait du wrapping/unwrapping de secrets Vault.

### Installation

```bash
# Créer l'utilisateur
sudo useradd --system --home /opt/rbi-proxy --shell /bin/false rbi-proxy
sudo mkdir -p /opt/rbi-proxy
sudo mkdir -p /etc/rbi-proxy

# Installer Node.js
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt install -y nodejs

# Déployer le code (adapter selon votre implémentation)
sudo chown -R rbi-proxy:rbi-proxy /opt/rbi-proxy
cd /opt/rbi-proxy
sudo -u rbi-proxy npm install express axios
```

### /etc/rbi-proxy/env

```
VAULT_ADDR=https://vault.example.com:8200
VAULT_TOKEN=<TOKEN_AVEC_DROITS_WRAPPING>
NODE_TLS_REJECT_UNAUTHORIZED=0
PORT=3001
```

### /etc/systemd/system/rbi-proxy.service

```ini
[Unit]
Description=RBI Proxy Service for Vault TOTP Injection
After=network.target

[Service]
Type=simple
User=rbi-proxy
Group=rbi-proxy
WorkingDirectory=/opt/rbi-proxy
EnvironmentFile=/etc/rbi-proxy/env
ExecStart=/usr/bin/node /opt/rbi-proxy/server.js
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rbi-proxy
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/rbi-proxy

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable rbi-proxy
sudo systemctl start rbi-proxy
```

---

## Étape 9 — Configuration du client RDVAULT

Dans le fichier `config.cfg` installé avec le client :

```ini
# URL du serveur Vault
VAULT_URL=https://vault.example.com:8200

# Chemin d'authentification LDAP
LDAP_AUTH_PATH=auth/ldap

# Domaines de confiance pour les certificats auto-signés
# (inutile si vous utilisez Let's Encrypt)
TRUSTED_DOMAINS=vault.example.com,<IP_SERVEUR>,localhost,127.0.0.1

# URL du proxy RBI (laisser vide si non utilisé)
RBI_PROXY_URL=http://<IP_SERVEUR>:3001

# Mode Enterprise (par défaut)
APP_MODE=enterprise

# Langue par défaut
LANG=en
```

---

## Étape 10 — Firewall

```bash
# Ports à ouvrir
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 8200/tcp  # Vault API (HTTPS)
sudo ufw allow 3001/tcp  # RBI Proxy (si utilisé)
# sudo ufw allow 8201/tcp  # Vault Cluster (si multi-node)
sudo ufw enable
```

---

## Vérification

```bash
# Depuis le serveur
vault status
vault auth list
vault secrets list

# Depuis un poste client (PowerShell)
curl -k https://vault.example.com:8200/v1/sys/health
```

---

## Maintenance

### Renouveler le certificat TLS

```bash
# Regénérer le certificat (même procédure qu'à l'étape 2)
# Puis recharger Vault sans downtime :
sudo systemctl reload vault
```

### Unseal après redémarrage

Vault se scelle à chaque redémarrage. Il faut fournir 3 des 5 clés unseal :

```bash
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_CACERT="/etc/vault-ssl/ca.pem"
vault operator unseal <KEY_1>
vault operator unseal <KEY_2>
vault operator unseal <KEY_3>
```

### Sauvegardes

```bash
# Snapshot Raft (sauvegarde complète)
vault operator raft snapshot save /backup/vault-$(date +%Y%m%d).snap

# Restauration
vault operator raft snapshot restore /backup/vault-YYYYMMDD.snap
```

---

## Résumé des composants

| Composant | Version | Port | Rôle |
|-----------|---------|------|------|
| HashiCorp Vault | 1.20.2 | 8200 (HTTPS) | Stockage des secrets, auth LDAP, PKI, TOTP |
| Raft (intégré) | — | 8201 | Stockage persistant (pas besoin de Consul) |
| RBI Proxy | Node.js | 3001 | Wrapping/unwrapping pour partage RBI (optionnel) |
| SSH | OpenSSH | 22 | Administration |
