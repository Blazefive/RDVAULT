# Vault Autofill - Extension Chrome

Extension Chrome pour auto-remplir les formulaires web avec vos identifiants stockés dans HashiCorp Vault.

## Fonctionnalités

- Authentification LDAP avec votre serveur Vault
- Détection automatique des champs login/password sur les pages web
- Auto-remplissage des identifiants basé sur l'URL du site
- Cache local des secrets (TTL: 5 minutes)
- Support KV v1 et KV v2
- Interface popup pour gérer la connexion

## Installation

### 1. Activer le mode développeur dans Chrome

1. Ouvrez Chrome et allez dans `chrome://extensions/`
2. Activez le "Mode développeur" (Developer mode) en haut à droite
3. Cliquez sur "Charger l'extension non empaquetée" (Load unpacked)
4. Sélectionnez le dossier `chrome-extension` de ce projet

### 2. Configurer les icônes (optionnel)

L'extension nécessite des icônes dans le dossier `icons/`:
- `icon16.png` (16x16 pixels)
- `icon48.png` (48x48 pixels)
- `icon128.png` (128x128 pixels)

Pour créer des icônes rapidement, vous pouvez :
1. Créer des images simples avec la lettre "V" (pour Vault)
2. Ou utiliser des générateurs d'icônes en ligne

### 3. Configurer CORS sur votre serveur Vault (si nécessaire)

Si votre serveur Vault n'accepte pas les requêtes de l'extension, ajoutez cette configuration :

```hcl
# config.hcl
ui = true

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true

  # Ajouter les en-têtes CORS
  cors_enabled = true
  cors_allowed_origins = ["chrome-extension://*"]
}
```

## Utilisation

### 1. Connexion à Vault

1. Cliquez sur l'icône de l'extension dans la barre d'outils Chrome
2. Entrez vos identifiants :
   - **URL Vault** : `http://192.168.1.15:8200` (ou votre serveur)
   - **Namespace** : Laisser vide si non utilisé
   - **Utilisateur LDAP** : Votre nom d'utilisateur
   - **Mot de passe** : Votre mot de passe
3. Cliquez sur "Se connecter"

### 2. Ajouter le champ "Website" à vos secrets

Pour que l'extension puisse matcher vos secrets avec les sites web, vous devez ajouter un champ `Website` à vos entrées Vault :

1. Ouvrez votre client Vault Desktop
2. Créez ou modifiez un secret
3. Remplissez le champ **Website** avec le domaine du site (ex: `github.com`, `google.com`)
4. Sauvegardez

**Exemple :**
- **Nom** : github-perso
- **Username** : mon-utilisateur
- **Password** : mon-mot-de-passe
- **URL** : https://github.com/login
- **Website** : `github.com` ← Important pour le matching
- **Notes** : Mon compte GitHub personnel

### 3. Auto-remplissage

1. Visitez un site web avec un formulaire de connexion (ex: https://github.com/login)
2. Si des identifiants matchent le domaine du site, une icône bleue "V" apparaît sur les champs de formulaire
3. Cliquez sur l'icône pour voir la liste des identifiants disponibles
4. Sélectionnez l'identifiant à utiliser
5. Les champs sont automatiquement remplis

### 4. Actualiser le cache

Si vous avez modifié vos secrets dans Vault :
1. Cliquez sur l'icône de l'extension
2. Cliquez sur "Actualiser le cache"

## Matching URL → Secrets

L'extension utilise le champ `Website` pour matcher les secrets avec les sites web :

- **Match exact** : `github.com` matche `github.com`
- **Sous-domaines** : `github.com` matche `login.github.com`
- **Flexible** : Supporte les URLs avec et sans protocole

**Ordre de priorité :**
1. Champ `Website` (recommandé pour l'extension)
2. Champ `URL` (utilisé en fallback)

## Architecture

```
chrome-extension/
├── manifest.json          # Configuration de l'extension
├── background.js          # Service Worker (gestion Vault API)
├── content.js             # Script injecté dans les pages web
├── popup.html/js          # Interface d'authentification
├── vault-client.js        # Client API Vault réutilisable
└── icons/                 # Icônes de l'extension
```

## Sécurité

- **Token** : Stocké dans `chrome.storage.local` (persistant mais sécurisé)
- **Cache** : TTL de 5 minutes pour limiter l'exposition
- **HTTPS recommandé** : Configurez votre serveur Vault en HTTPS en production
- **Permissions minimales** : L'extension demande uniquement les permissions nécessaires

## Dépannage

### L'icône "V" n'apparaît pas

1. Vérifiez que vous êtes connecté (cliquez sur l'icône de l'extension)
2. Vérifiez que vos secrets ont un champ `Website` rempli
3. Actualisez le cache depuis la popup
4. Rechargez la page web

### Erreur de connexion

1. Vérifiez que votre serveur Vault est accessible
2. Vérifiez les identifiants LDAP
3. Consultez la console du navigateur (`F12` → Console) pour les erreurs

### Erreur CORS

Si vous voyez des erreurs CORS dans la console :
1. Configurez CORS sur votre serveur Vault (voir section "Configurer CORS")
2. Redémarrez Vault
3. Rechargez l'extension

## Développement

Pour modifier l'extension :
1. Éditez les fichiers dans `chrome-extension/`
2. Retournez dans `chrome://extensions/`
3. Cliquez sur le bouton "Recharger" (icône circulaire) pour l'extension

Pour voir les logs :
- **Background script** : `chrome://extensions/` → "Inspecter les vues : service worker"
- **Content script** : `F12` dans la page web → Console
- **Popup** : Clic droit sur l'icône de l'extension → Inspecter

## Limitations actuelles

- Détection des formulaires basée sur les attributs HTML courants (peut ne pas fonctionner sur tous les sites)
- Cache limité à 5 minutes (rechargez manuellement si nécessaire)
- Pas de synchronisation en temps réel avec Vault

## Améliorations futures

- [ ] Support des formulaires avec TOTP
- [ ] Génération de mots de passe
- [ ] Sauvegarde automatique de nouveaux identifiants
- [ ] Synchronisation temps réel
- [ ] Support des identifiants multiples par domaine avec sélection intelligente
