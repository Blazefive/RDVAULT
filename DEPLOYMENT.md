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
- Accès réseau depuis les postes clients sur les ports 8200 (HTTPS) et 3001 (HTTPS)
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

> **Épinglage (`TRUSTED_CERT_FINGERPRINTS`)** : l'empreinte épinglée est celle du **certificat serveur** (SHA-256 du certificat, pas de la clé). Elle est contrôlée pour tout certificat présenté par l'hôte exact de `VAULT_URL`, y compris un certificat Let's Encrypt ou d'une CA d'entreprise reconnu par Windows. Chaque renouvellement (tous les 60 à 90 jours avec Let's Encrypt) change donc l'empreinte : voir « Maintenance › Renouveler le certificat TLS ».

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

### Durée des sessions RDVAULT

- RDVAULT renouvelle son jeton aux 2/3 de sa durée par `POST auth/token/renew-self`, autorisé par la policy `default` de Vault : gardez `default` dans les mappings de groupes (voir étape 7d). Sans ce droit, le jeton n'est pas renouvelé et la session se termine à son expiration.
- Vault ne renouvelle jamais au-delà de la durée maximale du jeton (`token_max_ttl` de `auth/ldap` ; à défaut, la durée maximale du montage ou du système). Une fois cette durée atteinte, ou si le jeton est révoqué, RDVAULT termine la session proprement (extension vidée, écran de connexion, message) et l'utilisateur se reconnecte. Exemple : `vault write auth/ldap/config token_ttl=1h token_max_ttl=10h`.
- Le délai d'inactivité de l'application (15 min) s'applique en plus, indépendamment de Vault.
- **MFA de connexion Vault** : non prise en charge. Un compte qui l'exige reçoit un message explicite et aucune session n'est ouverte.
- Vault scellé, en erreur (`5xx`) ou limitant les connexions (`429`) : message dédié, la tentative n'est pas décomptée par la protection anti-force brute du client.

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

> **Taille des coffres** : RDVAULT liste au plus 20 000 entrées et 20 niveaux de dossiers par coffre. Au-delà, il affiche les entrées déjà listées avec un avertissement (liste incomplète) et refuse de copier ou déplacer des entrées vers ce coffre, faute de pouvoir détecter les doublons. Répartissez les très gros ensembles dans plusieurs coffres.

> **KV v2 recommandé** : outre l'historique et la restauration des versions, il permet les écritures conditionnelles. Une copie ou un déplacement vers un coffre KV v2 écrit en création seule (`cas: 0`) et ne remplace jamais une entrée créée entre-temps sous le même nom par un autre poste ; KV v1 n'offre pas ce contrôle.

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
│ Modérateur   │ RW sur les coffres assignés. Consultation    │
│              │ seule des policies, coffres et groupes AD    │
│              │ (l'UI n'affiche que ceux qui concernent ses  │
│              │ coffres ; en lecture, Vault lui ouvre toutes │
│              │ les policies, la liste des coffres et les    │
│              │ groupes). Aucun accès au contenu des autres  │
│              │ coffres.                                     │
├──────────────┼──────────────────────────────────────────────┤
│ RW (écriture)│ Lecture + écriture sur un coffre spécifique. │
│              │ Peut créer/modifier/supprimer des secrets.   │
├──────────────┼──────────────────────────────────────────────┤
│ RO (lecture) │ Lecture seule sur un coffre. Voit les secrets│
│              │ mais ne peut pas les modifier. Marqué "RO?"  │
│              │ dans l'UI RDVAULT.                           │
├──────────────┼──────────────────────────────────────────────┤
│ Self-service │ Chaque utilisateur peut créer/gérer ses      │
│              │ propres coffres sous users/<username>/.      │
│              │ Aucun accès aux coffres des autres.          │
│              │ Pas de TOTP (voir la note TOTP, étape 7c).   │
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

> **Sécurité — délégation** : donner à un non-administrateur l'écriture (`create`, `update`, `delete`, `sudo`) sur `sys/policies/acl/*`, `sys/auth/*`, `auth/<méthode>/groups/*` (ou `users/*`), `identity/*` ou `sys/mounts/*` revient à lui donner `root` : il peut réécrire sa propre policy en `path "*"`, ajouter la policy `admin` à son groupe LDAP, ou monter un moteur d'authentification. Vault ne sait pas limiter le *contenu* d'une policy écrite. Seule la policy `admin` porte ces droits ; les modèles ci-dessous n'en donnent aucun autre (hors montage de ses propres coffres en self-service, chemin délimité par l'identité).

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

# Pas de droit TOTP ici : voir la note « TOTP et coffres personnels »
EOF
```

> **TOTP et coffres personnels** : RDVAULT nomme une clé TOTP `<COFFRE>-<entrée>`, où `<COFFRE>` est le nom du coffre en majuscules **sans** le préfixe `users/<nom>/` (format existant des clés déjà créées). Le nom de clé ne contient donc pas le propriétaire : `users/alice/perso` et `users/bob/perso` produisent tous deux des clés `PERSO-…`, et un chemin `TOTP/…` ne peut pas être limité à l'utilisateur avec `{{identity…}}`. Les anciennes lignes `path "TOTP/keys/*"` / `path "TOTP/code/*"` de ce modèle donnaient à **chaque** utilisateur la liste, la lecture des codes, le remplacement et la suppression des clés TOTP de **tous** les coffres (y compris les coffres partagés auxquels il n'a pas accès) : retirez-les des policies déjà déployées. Conséquence : en mode Vault, pas de TOTP sur les coffres personnels, sauf droit accordé explicitement par préfixe (`TOTP/code/PERSO-*`…), en sachant que ce préfixe est commun aux coffres personnels homonymes de tous les utilisateurs.

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

> **Préfixes TOTP** : dans une policy Vault, un `*` final désigne un **préfixe**. `TOTP/code/WEB-*` (coffre `web`) couvre donc aussi les clés du coffre `web-prod` (`WEB-PROD-…`). Choisissez des noms de coffres dont aucun n'est le début d'un autre suivi d'un tiret (évitez `web` et `web-prod`), ou acceptez ce partage. Le builder du panneau d'administration signale les coffres connus concernés.

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

### Policy Modérateur — RW + consultation des policies/engines/groupes

Même policy que celle générée par le builder (niveau « Modérateur ») : écriture sur le contenu des coffres gérés, **lecture seule** sur les chemins système.

```bash
vault policy write moderateur - <<'EOF'
# Lister les coffres
path "sys/mounts"   { capabilities = ["read","list"] }
path "sys/mounts/*" { capabilities = ["read","list"] }

# KV v2 MODERATOR (MonCoffre)
path "MonCoffre/metadata/*" { capabilities = ["list","read","delete"] }
path "MonCoffre/data/*"     { capabilities = ["create","update","read","delete","list"] }
path "MonCoffre/delete/*"   { capabilities = ["update"] }
path "MonCoffre/undelete/*" { capabilities = ["update"] }
path "MonCoffre/destroy/*"  { capabilities = ["update"] }

# TOTP (MONCOFFRE-*)
path "TOTP/keys/MONCOFFRE-*"     { capabilities = ["create","update","read","delete"] }
path "TOTP/code/MONCOFFRE-*"     { capabilities = ["read"] }
path "TOTP/validate/MONCOFFRE-*" { capabilities = ["update"] }

# Permissions modérateur : lecture seule des policies, mounts et groupes AD + tags partagés
path "sys/policies/acl"     { capabilities = ["list"] }
path "sys/policies/acl/*"   { capabilities = ["read","list"] }
path "sys/mounts"           { capabilities = ["read","list"] }
path "sys/mounts/*"         { capabilities = ["read","list"] }
path "auth/ldap/groups"     { capabilities = ["list"] }
path "auth/ldap/groups/*"   { capabilities = ["read","list"] }
# Accès au coffre des tags partagés
path "tags-shared/metadata/*" { capabilities = ["list","read"] }
path "tags-shared/data/*"     { capabilities = ["create","update","read","list"] }
EOF
```

> **Note** : RDVAULT détecte le rôle modérateur grâce au commentaire `# KV v2 MODERATOR (NomCoffre)` (ou `# KV v1 MODERATOR (NomCoffre)` pour un coffre KV v1), placé juste avant les règles du coffre, une ligne par coffre géré. Le plus simple est de générer la policy avec le builder (niveau « Modérateur »). Ce commentaire ne sert qu'à l'interface : les droits réels sont ceux des règles `path`. Le modérateur voit, dans le panneau d'administration, ses coffres et les policies et groupes AD qui les concernent, **en consultation seule** (ce filtrage est celui de l'interface : les règles `read`/`list` ci-dessus lui permettent de lire toutes les policies, la liste des coffres et les groupes LDAP directement auprès de Vault, sans accès au contenu des autres coffres) : la création ou suppression de coffres, l'écriture des policies et la liaison des groupes restent réservées aux administrateurs (voir l'avertissement « Sécurité — délégation » ci-dessus). Si une ancienne version de ce modèle (écriture sur `sys/policies/acl/*`, `sys/mounts/*` ou `auth/ldap/groups/*`, marqueur `# MODERATOR:`) est déployée, remplacez-la.

### Niveau « RBI uniquement » du builder — limite

Le niveau « RBI uniquement » est une restriction d'interface, pas une restriction Vault. La policy générée donne exactement les mêmes droits Vault que « Lecture seule » (`read` sur `<coffre>/data/*` ou sur le secret, plus `TOTP/code/<PRÉFIXE>-*`) : RDVAULT lit l'identifiant avec le jeton de l'utilisateur, puis l'injecte dans la session isolée. Le commentaire `# RBI-ONLY` sert uniquement à l'application, qui masque alors identifiant, mot de passe et notes et force l'ouverture en session sécurisée. L'utilisateur peut donc toujours lire le mot de passe et obtenir le code TOTP hors de RDVAULT avec son propre jeton (`vault login -method=ldap` puis `vault kv get`, API, curl). Une vraie barrière demanderait qu'un service privilégié lise et injecte le secret à la place du poste client, ce que RDVAULT ne propose pas aujourd'hui. N'utilisez pas ce niveau pour des comptes dont l'utilisateur ne doit en aucun cas connaître le mot de passe.

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

# Modérateurs — RW sur leurs coffres, consultation des policies et groupes
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

### Exigences de sécurité (obligatoires)

Le proxy manipule des identifiants en clair et détient un token Vault privilégié. Le client RDVAULT **refuse** une `RBI_PROXY_URL` qui n'est pas en `https://`. L'implémentation de `server.js` doit respecter les points suivants, sans quoi tout partage RBI est exposé :

1. **TLS obligatoire** : servir en HTTPS avec un certificat valide pour les postes clients (CA d'entreprise), ou derrière un reverse proxy TLS (nginx/caddy). Jamais `NODE_TLS_REJECT_UNAUTHORIZED=0` : installer la CA dans le magasin système du serveur (`/usr/local/share/ca-certificates/` + `update-ca-certificates`) ou utiliser `NODE_EXTRA_CA_CERTS=/etc/rbi-proxy/vault-ca.crt`.
2. **Authentification de chaque appel** : `POST /create-share` et `POST /unwrap-rbi` doivent exiger un token Vault du demandeur (header `X-Vault-Token`) que le proxy vérifie par `GET /v1/auth/token/lookup-self` avant d'agir. Aucun endpoint anonyme.
3. **Aucune persistance des identifiants** : le proxy ne doit jamais unwrap le token de partage à la création. Il stocke uniquement le wrapping token et le rend au destinataire authentifié, qui unwrap lui-même auprès de Vault. Le wrapping token Vault est à usage unique : cela garantit qu'un partage ne peut être consommé qu'une fois.
4. **Limites** : `maxUses` plafonné à 5 (pas d'illimité), TTL maximal 24 h, `shareId` généré avec `crypto.randomBytes(32)`, limitation de débit par IP et par token.
5. **Token du proxy** : policy Vault minimale (`sys/wrapping/lookup` et `sys/wrapping/unwrap` uniquement si le point 3 l'exige, sinon aucun accès aux secrets) ; ne jamais lui donner `TOTP/code/*`.
6. **Journalisation** sans identifiants : consigner `shareId`, demandeur (entity), horodatage, résultat.
7. **Code versionné** : `server.js` doit être dans un dépôt revu, avec les mêmes exigences d'audit que le client.

### Contrat d'API attendu par le client RDVAULT

Le client applique ces règles de son côté et refuse un proxy qui ne les suit pas.

| Appel | En-têtes | Corps envoyé | Réponse attendue |
|---|---|---|---|
| `POST /create-share` | `X-Vault-Token` (jeton du demandeur), `Content-Type: application/json` | `{ wrappingToken, maxUses, ttl }` : `maxUses` vaut 1, 2, 3 ou 5, `ttl` vaut `1h`, `8h` ou `24h` | `{ shareId }` (lettres, chiffres, `-` ou `_`, 128 caractères au plus) |
| `POST /unwrap-rbi` | `X-Vault-Token` (jeton du destinataire), `Content-Type: application/json` | `{ shareId }` | `{ wrappingToken }` ; erreurs : `404` partage inconnu, `410` utilisations épuisées, `400` expiré, `401` / `403` non autorisé |

- Le client crée lui-même le wrapping token (`sys/wrapping/wrap`, TTL choisi) avec l'adresse, l'identifiant, le mot de passe et, le cas échéant, l'adresse « site web » de l'entrée (domaine où la saisie reste autorisée) et le **nom** de la clé TOTP. Ce contenu n'est lisible qu'après unwrap : le proxy ne le voit jamais. Le destinataire l'unwrappe lui-même auprès de Vault, confirme l'ouverture (adresse et identifiant affichés), puis lit le code TOTP avec **son propre** jeton s'il y a droit.
- Un proxy qui renvoie des identifiants en clair au lieu de `{ wrappingToken }` (ancienne implémentation) est refusé.
- Le wrapping token Vault est à usage unique : même avec `maxUses` supérieur à 1, seul le premier unwrap réussit.
- En mode entreprise, l'application autorise l'origine `https` de `RBI_PROXY_URL` dans sa politique de sécurité du contenu (CSP) : aucun réglage n'est nécessaire côté poste.

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
VAULT_TOKEN=<TOKEN_AVEC_DROITS_WRAPPING_UNIQUEMENT>
# CA d'entreprise pour valider le certificat Vault (ne JAMAIS désactiver la vérification TLS)
NODE_EXTRA_CA_CERTS=/etc/rbi-proxy/vault-ca.crt
PORT=3001
# Certificat TLS du proxy lui-même (https obligatoire côté client RDVAULT)
TLS_CERT=/etc/rbi-proxy/rbi-proxy.crt
TLS_KEY=/etc/rbi-proxy/rbi-proxy.key
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

L'installeur est **par machine** (Program Files, droits administrateur). Pour un déploiement de masse, déposer la configuration dans `%PROGRAMDATA%\RDVAULT\config.cfg` (lu en priorité, modifiable uniquement par les administrateurs) ; sinon dans le dossier d'installation via `/CONFIG=`. Chaque valeur est validée au démarrage et remplacée par un défaut sûr si elle est invalide.

**Extension enrichie et postes multi-sessions** : la liaison avec l'extension utilise le port local fixe `45678`, commun à toutes les sessions Windows d'un poste (bureau à distance, Citrix, changement rapide d'utilisateur). Seule la première instance RDVAULT l'écoute ; les suivantes affichent un avertissement, et l'extension d'une autre session joindrait l'application de la première. Ne déployez pas l'extension enrichie sur des serveurs de sessions partagés (voir `SECURITY.md`).

Dans le fichier `config.cfg` installé avec le client :

```ini
# URL du serveur Vault
VAULT_URL=https://vault.example.com:8200

# Chemin d'authentification LDAP
LDAP_AUTH_PATH=auth/ldap

# Domaines de confiance pour les certificats auto-signés
# (inutile si vous utilisez Let's Encrypt)
TRUSTED_DOMAINS=vault.example.com,<IP_SERVEUR>,localhost,127.0.0.1

# URL du proxy RBI (laisser vide si non utilisé ; https obligatoire, sinon ignorée)
RBI_PROXY_URL=https://rbi-proxy.example.com:3001

# Empreintes SHA-256 des certificats acceptés (pinning, recommandé) : tout certificat de l'hôte de VAULT_URL,
# même reconnu par Windows, et les certificats auto-signés des TRUSTED_DOMAINS
# openssl x509 -in vault.crt -noout -fingerprint -sha256
TRUSTED_CERT_FINGERPRINTS=

# Mode Enterprise (par défaut)
APP_MODE=enterprise

# Langue par défaut
LANG=en
```

Remarques :

- **Encodage** : enregistrez `config.cfg` de préférence en **UTF-8** (avec ou sans BOM). Un fichier UTF-16 (petit ou grand boutiste, avec ou sans BOM : Bloc-notes « Unicode », sortie par défaut de `Out-File` et de la redirection `>` sous Windows PowerShell 5.1) est lu aussi, avec un avertissement dans le journal. Un fichier non vide dont aucune clé n'est reconnue est signalé dans le journal, et l'application démarre avec les valeurs par défaut. Sous PowerShell 5.1, `Set-Content -Encoding UTF8` ou `Out-File -Encoding utf8` produisent de l'UTF-8.
- **`VAULT_URL` et `RBI_PROXY_URL`** : `https://` obligatoire, sans identifiants. L'application les normalise au démarrage : barre finale, paramètres (`?…`) et fragment (`#…`) retirés, préfixe de chemin d'un proxy inverse conservé. Pour `VAULT_URL`, un suffixe `/v1` collé par erreur est retiré (l'application l'ajoute) ; la correction est journalisée.
- **`TRUSTED_CERT_FINGERPRINTS`** : liste d'empreintes séparées par des virgules. Si elle est renseignée, tout certificat présenté par l'hôte exact de `VAULT_URL` doit y figurer, **même s'il est reconnu par le magasin Windows** (CA publique, CA d'entreprise, boîtier d'inspection TLS) : un boîtier d'inspection TLS qui intercepte le trafic Vault est alors refusé. Pour les autres hôtes, seuls les certificats jugés invalides (auto-signés) sont contrôlés : un certificat auto-signé d'un autre hôte de `TRUSTED_DOMAINS` (proxy RBI, par exemple) doit lui aussi figurer dans la liste ; un certificat valide d'un autre hôte suit la seule confiance du magasin Windows. Vide : confiance du magasin Windows, plus `TRUSTED_DOMAINS` pour les certificats auto-signés. **Au renouvellement d'un certificat épinglé, ajoutez sa nouvelle empreinte avant de le déployer** (voir « Maintenance »), sinon les postes refusent le serveur.
- **Installation silencieuse** : `/S /CONFIG=chemin\config.cfg` copie le fichier tel quel dans le dossier d'installation (toutes les clés), `/MODE=local|enterprise` ne remplace que `APP_MODE`. Fichier illisible ou mode invalide : arrêt avec le code `2`, rien n'est modifié.
- **Mise à jour du client** : silencieuse ou interactive, elle conserve `config.cfg` à l'octet près (épinglage et langue compris) et l'appairage de l'extension. Pendant une mise à jour, `/CONFIG=` remplace la configuration et `/MODE=` seulement `APP_MODE`.

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

> **Avec l'épinglage (`TRUSTED_CERT_FINGERPRINTS`)** : le nouveau certificat a une autre empreinte, et les postes refusent tout certificat absent de la liste, même signé par une autorité reconnue. Procédez en deux temps : (1) générez le nouveau certificat, calculez son empreinte (`openssl x509 -in vault.crt -noout -fingerprint -sha256`) et **ajoutez-la** à `TRUSTED_CERT_FINGERPRINTS` sur les postes, à côté de l'ancienne ; (2) installez le certificat sur Vault, puis retirez l'ancienne empreinte au déploiement suivant. Avec Let's Encrypt, le renouvellement automatique change l'empreinte à chaque fois : réservez l'épinglage aux certificats dont vous maîtrisez la date de remplacement.

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
| RBI Proxy | Node.js | 3001 (HTTPS) | Relais de wrapping tokens pour partage RBI (optionnel, endpoints authentifiés) |
| SSH | OpenSSH | 22 | Administration |
