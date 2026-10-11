# Passkeys (WebAuthn / FIDO2) — RDVAULT

L'extension enrichie fournit des passkeys logicielles : quand un site appelle l'API
WebAuthn, RDVAULT propose sa passkey dans une fenêtre, comme le font Bitwarden ou
1Password. Implémentation indépendante de la spécification W3C WebAuthn (aucun code
tiers copié ; projet sous licence MIT).

## Architecture

```
Page web
  │  navigator.credentials.create / get
  ▼
passkey-inject.js   (monde MAIN, contexte de la page)
  │  - remplace create/get ; AUCUNE crypto, AUCUNE clé privée ici
  │  - sérialise la requête, la relaie par window.postMessage
  ▼
passkey-bridge.js   (monde ISOLÉ)
  │  - valide le rp.id contre l'origine réelle de la frame
  │  - affiche la fenêtre de choix (shadow root fermé)
  │  - fait toute la crypto via passkey-core.js
  │  - stocke / lit les passkeys via le service worker
  ▼
background.js  →  serveur sync 127.0.0.1:45678  (appairé + token)
  │                 /api/passkey (POST), /api/passkeys (GET), /api/passkey/count (POST)
  ▼
app desktop (renderer)  →  COFFRE RDVAULT chiffré
                            secret interne « .rdvault-passkeys » (clés privées incluses)
```

La clé privée ne quitte jamais le monde isolé : la page ne reçoit que les éléments
publics (attestation / assertion). `passkey-core.js` contient le moteur FIDO2 (ES256,
P-256, attestation « none », CBOR/COSE, authenticatorData, signature DER).

## Choix proposé à l'utilisateur

- **Utiliser RDVAULT** : crée/utilise la passkey RDVAULT.
- **Utiliser un autre appareil** : bascule vers l'authentificateur natif du navigateur
  (Windows Hello, clé de sécurité, téléphone).
- **Annuler** : renvoie l'erreur WebAuthn standard `NotAllowedError`.

Si RDVAULT n'a aucune passkey pour le site (authentification), la main est rendue
automatiquement au navigateur, sans fenêtre.

Les libellés de la fenêtre (cités ici en français) s'affichent dans la langue du navigateur
(`chrome.i18n`, 12 langues, de droite à gauche en arabe). Ils sont produits par le pont (monde
isolé) ; `passkey-inject.js` (monde de la page) n'affiche aucun texte.

## Cas laissés au navigateur (sans fenêtre RDVAULT)

- **Médiation « conditional »** (`navigator.credentials.get/create({ mediation: 'conditional' })`,
  l'autofill de passkeys que de nombreux sites lancent dès le chargement de la page de
  connexion) : WebAuthn interdit toute fenêtre modale pour ces requêtes. RDVAULT ne s'intègre
  pas à l'autofill natif ; `passkey-inject.js` transmet donc la requête telle quelle au
  navigateur, sans fenêtre ni consultation du coffre.
- **Iframe sans délégation** : dans une frame autre que la page principale, RDVAULT n'intervient
  que si la Permissions-Policy l'autorise (`document.featurePolicy.allowsFeature(
  'publickey-credentials-create' | 'publickey-credentials-get')`, c'est-à-dire même origine ou
  attribut `allow="publickey-credentials-…"` posé par l'embarqueur). Sinon le navigateur applique
  la politique et renvoie son erreur standard (`NotAllowedError`) : un site tiers ne peut pas
  faire apparaître la fenêtre RDVAULT dans une page qu'il encadre. Hors contexte sécurisé, même
  traitement.
- **rp.id non enregistrable** : le `rp.id` doit être l'hôte de la frame ou un domaine parent
  *enregistrable*. Sont refusés (renvoyés au navigateur, qui les rejette lui-même) : un TLD seul
  (`com`), un suffixe public (`co.uk`, `com.au`, `github.io`, `vercel.app`…) et tout suffixe
  partiel d'une adresse IP. Sans cette règle, une passkey créée avec `rp.id = "com"` serait
  partagée entre tous les sites en `.com`. La détection des suffixes publics repose sur une
  liste partielle de la Public Suffix List (hébergeurs mutualisés courants) et sur le motif des
  seconds niveaux de ccTLD ; un faux positif ne bloque rien, il laisse l'authentificateur natif.
- **Algorithme ES256 absent** de `pubKeyCredParams`, **iframe aux ancêtres inconnus** : voir
  « Limites connues » (points 8 et 9).

Une requête `userVerification: 'required'` n'est **pas** laissée au navigateur : RDVAULT la sert
(voir « Vérification de l'utilisateur »).

## Vérification de l'utilisateur (drapeau UV)

**Choix de conception : le déverrouillage du coffre par le mot de passe maître constitue la
vérification de l'utilisateur**, comme chez les gestionnaires de mots de passe du marché qui
fournissent des passkeys. Une passkey RDVAULT n'existe que dans le coffre chiffré, lisible
seulement une fois l'application déverrouillée par ce mot de passe ; une cérémonie servie par
RDVAULT n'aboutit que dans cet état :

- **authentification** : la clé privée est lue dans le coffre (`PASSKEY_LIST`) et le compteur y
  est réservé (`PASSKEY_UPDATE_COUNT`) **avant** la signature ;
- **création** : l'attestation n'est renvoyée au site qu'**après** l'enregistrement de la clé dans
  le coffre (`PASSKEY_STORE`), sinon `NotAllowedError`.

Le drapeau **UV** (« user verified ») est donc posé, en plus de UP : `0x45` (UP | UV | AT) à la
création, `0x05` (UP | UV) à l'authentification. `userVerification: 'required'` (création comme
authentification) est **servi par RDVAULT** ; `preferred` et `discouraged` reçoivent aussi UV=1.
Les sites qui vérifient UV, réglage par défaut de nombreux serveurs (par exemple
`@simplewebauthn/server`, `requireUserVerification: true`), acceptent ainsi les passkeys RDVAULT.

Coffre **verrouillé ou application fermée** : aucune passkey n'est lisible, rien n'est signé.
L'authentification est laissée au navigateur (aucune passkey RDVAULT proposée) et la création est
refusée (`NotAllowedError`, voir « Coffre indisponible »). Le clic dans la fenêtre RDVAULT est le
geste de présence (UP) ; il ne redemande pas le mot de passe maître.

C'est l'état final, identique au comportement des versions publiées (1.6.0 et 1.7.0), qui posaient
déjà UV : les passkeys existantes ne voient aucun changement. Un retrait temporaire d'UV (UP seul,
`required` renvoyé au navigateur) a existé pendant le développement ; il **n'a jamais été publié**
et a été abandonné, car il rendait les passkeys RDVAULT inutilisables sur les sites qui vérifient
UV, y compris des passkeys déjà enregistrées avec UV=1.

Le choix est fixé dans le pont (`passkey-bridge.js`, constante `VAULT_UNLOCK_VERIFIES_USER`) ;
le moteur (`passkey-core.js`) ne pose UV que si l'appelant l'atteste (`userVerified: true`),
sinon UP seul.

## Coffre indisponible

La clé privée n'existe que dans le coffre. Si l'enregistrement échoue (app fermée,
verrouillée, non appairée, écriture refusée), `create()` est **rejeté** (`NotAllowedError`
standard) : le site n'enregistre jamais une clé publique dont la clé privée serait perdue, et
peut proposer de réessayer une fois RDVAULT déverrouillé. En authentification, un coffre
indisponible ne fournit aucune passkey : la main est rendue au navigateur, sans fenêtre RDVAULT.

**Compteur de signatures réservé avant la signature.** Après le clic, et avant de signer, le pont
réserve dans le coffre la valeur suivante du compteur (`PASSKEY_UPDATE_COUNT`) : l'application
n'accepte qu'une valeur strictement supérieure à celle stockée ; sinon (valeur déjà consommée par
un autre onglet ou un autre poste pendant que la fenêtre était ouverte) elle répond
`{ reserved: false, signCount: <valeur stockée> }` et le pont demande la suivante (5 essais au
plus). L'assertion est signée avec la valeur réservée : le compteur vu par le site est strictement
croissant (jamais 6, 7 puis 6). Si la réservation échoue (coffre fermé, verrouillé, illisible),
**aucune assertion n'est renvoyée** (`NotAllowedError`) : sinon la suivante rejouerait le même
compteur et un site qui vérifie sa progression la refuserait, voire désactiverait la clé. Une
application de bureau antérieure, qui ne renvoie pas le champ `reserved`, enregistre la valeur
telle quelle (comportement d'origine).

**`excludeCredentials`.** Si le site fournit `excludeCredentials` et qu'une passkey RDVAULT de
cette liste existe déjà pour le `rpId`, la création est refusée par l'erreur WebAuthn standard
`InvalidStateError` — après le clic de consentement, pour que le site ne puisse pas sonder sans
geste de l'utilisateur l'existence d'une passkey — et aucune passkey n'est ajoutée. Si le coffre est
indisponible à ce moment, l'exclusion est invérifiable : la création est refusée
(`NotAllowedError`), comme toute création dans un coffre indisponible.

## Sécurité de la fenêtre (anti-clickjacking)

La fenêtre est insérée dans le DOM de la page (shadow root fermé). Le shadow root protège son
contenu, mais la page garde la main sur l'élément hôte : elle pourrait le rendre invisible
(`opacity: 0 !important`, masque CSS), le recouvrir d'un élément `pointer-events: none` ou
l'imbriquer sous un effet, et amener l'utilisateur à cliquer, par un vrai clic, sur un leurre
placé exactement au-dessus du bouton « Utiliser ma passkey » ou d'un compte.

Les boutons qui **signent ou créent** (bouton principal, boutons de compte) ne sont donc
« armés » que si toutes les conditions suivantes sont réunies au moment du clic :

1. clic réel (`event.isTrusted`) ;
2. boîte vue **entière, visible et non recouverte** par `IntersectionObserver` v2
   (`trackVisibility: true`, `isVisible === true`, ratio d'intersection ≥ 0,99) ;
3. depuis au moins **500 ms** (délai d'armement, comme les bulles de permission du navigateur :
   un double-clic ou un clic « au vol » sur une fenêtre qui vient d'apparaître est ignoré) ;
   toute perte de visibilité remet ce délai à zéro ;
4. aucun effet masquant sur l'hôte ni sur `<html>` (opacité, `visibility`, filtre, `clip-path`,
   `mix-blend-mode`, `mask-image`) : le masque CSS notamment échappe à IntersectionObserver v2 ;
   l'hôte doit toujours être un enfant direct de `<html>` ;
5. l'hôte est l'élément au premier plan au centre du bouton (`document.elementFromPoint`).

Si un clic est refusé pour une raison de visibilité, un avertissement s'affiche dans la fenêtre.
« Utiliser un autre appareil » (qui ouvre l'UI native du navigateur, que la page ne peut ni
masquer ni styler) et « Annuler » ne sont pas conditionnés : ils ne produisent aucune signature.

Choix de conception : IntersectionObserver v2 fonctionne dans Chrome / Chromium (y compris le
Chrome for Testing des tests e2e, fenêtre affichée) ; les contrôles 3 à 5 ne dépendent pas de
lui et restent actifs s'il n'est pas disponible. Mesuré dans Chrome 154 : `isVisible` devient
vrai environ 300 ms après l'insertion (animation d'apparition comprise), faux pour un hôte
`opacity: 0 !important`, un recouvrement `pointer-events: none`, un filtre sur `<html>` ; il
reste vrai pour un `mask-image` sur l'hôte, d'où le contrôle 4.

## Plusieurs comptes pour un même site

Quand plusieurs passkeys RDVAULT existent pour un même `rpId` (plusieurs comptes sur le
site, ou flux « discoverable » où le site appelle `get` sans `allowCredentials`), la fenêtre
remplace le bouton unique par **un bouton par compte** : nom affiché (ou identifiant), puis
en sous-ligne l'identifiant et la date de création. Le compte cliqué est celui qui signe
l'assertion (son `credentialId`, sa clé, son `userHandle`). Seuls des champs publics du
coffre sont affichés, injectés en `textContent` (jamais en HTML) ; la clé privée reste dans
le monde isolé. « Utiliser un autre appareil » et « Annuler » (→ `NotAllowedError`) gardent
le même comportement. Si le site fournit `allowCredentials` et qu'une seule passkey
correspond, la confirmation simple est conservée.

## Tests

```bash
npm run test:passkey       # moteur FIDO2 (crypto) + relais inject/pont simulés + parcours complet
                           # inject ↔ pont ↔ cœur dans jsdom (webauthn-flow.test.js), Node
npm run test:e2e:passkey   # bout en bout dans Chrome (création + auth + vérif signature + multi-comptes
                           # + coffre indisponible + anti-clickjacking + conditional + iframes
                           # + serveur exigeant UV + une seule version du blob)
npm run test:smoke         # coffre local : purge des versions des blobs .rdvault-* (PURGE-35)
```

Le cas « serveur exigeant UV » du test e2e crée puis utilise une passkey avec
`userVerification: 'required'` ; le test joue le rôle du serveur et vérifie les réponses comme
`@simplewebauthn/server` avec son réglage par défaut : `clientDataJSON` (type, challenge,
origine), `rpIdHash`, drapeaux UP **et UV**, signature ES256 avec la clé publique enregistrée,
compteur croissant.

Le test e2e pilote la fenêtre de choix par le protocole DevTools (`DOM.getDocument` avec
`pierce: true` traverse le shadow root fermé, puis clic réel `Input.dispatchMouseEvent`,
donc `isTrusted`), après le délai d'armement de la fenêtre. Le scénario multi-comptes crée
une seconde passkey (« Bob ») pour le même `rpId`, lance un `get` sans `allowCredentials`,
clique le bouton de compte contenant « Bob » et vérifie la signature avec la clé publique de
ce compte. Il vérifie aussi : `create()` rejeté quand l'app n'est pas lancée ; clic immédiat
ignoré puis accepté une fois la fenêtre armée ; aucune assertion pour une fenêtre rendue
invisible, recouverte (`pointer-events: none`) ou masquée (`mask-image`), et ré-armement une
fois le recouvrement retiré ; aucune fenêtre pour `mediation: 'conditional'` ; `challenge` et
`allowCredentials` passés en sous-vue typée ; iframe cross-origin refusée sans `allow`,
acceptée avec `allow="publickey-credentials-get"`. Les tests Node valident en plus, sur les
scripts réels exécutés avec un `window` simulé, l'encodage des vues typées, la médiation
conditionnelle, le refus des `rp.id` suffixes publics et la Permissions-Policy.

Validation serveur réelle effectuée sur https://webauthn.io (enregistrement et
authentification acceptés).

## Stockage

Les passkeys sont dans le **coffre RDVAULT chiffré**, agrégées dans un secret interne
`.rdvault-passkeys` du coffre personnel, masqué de la liste affichée et de la synchronisation
d'autofill. La clé privée n'est transmise à l'extension qu'au moment de signer (même modèle de
confiance que les mots de passe). L'écriture passe par le renderer (seul détenteur du token Vault)
via le serveur sync.

- **Coffre personnel exact** : coffre dont le nom commence par `users/<nom>/`, où `<nom>` est le
  nom de connexion **tel quel** (casse ignorée, sans assainissement : `jean.dupont`,
  `j.doe@corp.fr`, `Élodie`, `jean dupont` sont des noms valides) ; `Mes-Secrets` de préférence
  s'il en existe plusieurs.
- **Plus de repli** : jamais le coffre d'un autre utilisateur ni le premier coffre venu. Sans
  coffre personnel, les passkeys sont indisponibles : la création est refusée et l'authentification
  est laissée au navigateur.
- **Ancien emplacement relu en lecture seule** : l'ancien code assainissait le nom
  (`jean.dupont` → `jeandupont`) et se rabattait sur un autre coffre ; il a pu écrire les passkeys
  ailleurs. Tant que le coffre personnel n'a pas de blob, l'emplacement que l'ancien algorithme
  aurait choisi est **relu**, uniquement s'il appartient à l'utilisateur courant (jamais le coffre
  d'autrui) ; seul le coffre personnel est écrit (le contenu hérité y est recopié à la première
  écriture) et l'ancien blob n'est jamais supprimé. Format, nom de clé et chiffrement inchangés.
- Les lectures-modifications-écritures du blob sont sérialisées (file d'attente unique ; en KV v2,
  écriture conditionnelle `cas` rejouée en cas de conflit avec un autre poste). Le coffre local
  applique `options.cas` comme Vault (`400` si la version a changé, rien n'est écrit) : la
  protection vaut dans les deux modes.
- **Une seule version conservée (coffre local)** : le blob contient toutes les clés privées et il
  est réécrit à chaque création, suppression et signature (réservation du compteur). Pour les blobs
  internes cachés `.rdvault-*` uniquement (`.rdvault-passkeys`, `.rdvault-keycheck`), le coffre
  local efface les versions précédentes dans la transaction d'écriture, puis vide le journal WAL
  (`wal_checkpoint(TRUNCATE)`) ; avec `secure_delete`, les octets effacés sont remis à zéro. Une
  passkey supprimée dans « Mes passkeys » n'est donc plus lisible par `GET …?version=N` ni présente
  dans les fichiers de la base, et les signatures ne font plus grossir la base. La numérotation des
  versions continue (la métadonnée `oldest_version` égale `current_version`). Les entrées normales
  gardent tout leur historique. Le vidage du journal se fait au mieux : si une lecture en cours
  l'empêche, le point de contrôle automatique suivant prend le relais. Les sauvegardes et copies
  antérieures de la base gardent les anciennes versions. Un coffre antérieur à cette purge garde
  ses anciennes versions jusqu'à la prochaine écriture du blob (création, suppression ou
  utilisation d'une passkey), qui les efface.
- **Mode HashiCorp Vault** : la conservation des versions relève du serveur (`max_versions` du
  moteur KV v2, 10 par défaut) ; RDVAULT ne détruit aucune version. Une passkey supprimée y reste
  dans les versions précédentes du blob, lisibles avec le droit de lecture du coffre, jusqu'à ce
  qu'elles sortent de cette fenêtre. Pour l'éviter, l'administrateur peut fixer `max_versions = 1`
  sur la clé (`POST <moteur>/metadata/.rdvault-passkeys`, corps `{ "max_versions": 1 }`) ou
  détruire les anciennes versions (`POST <moteur>/destroy/.rdvault-passkeys`, corps
  `{ "versions": [ … ] }`).
- **Ancien emplacement** : relu en lecture seule et jamais modifié (voir ci-dessus), il garde les
  passkeys qu'il contenait au moment de la recopie, y compris celles supprimées ensuite depuis le
  coffre personnel.

## Attestation

- Par défaut : « none ».
- Si le site demande une attestation (`direct`/`enterprise`) : auto-attestation « packed »
  (format `packed`, signée par la clé de la passkey, sans x5c, AAGUID nul). Prouve la
  possession de la clé mais pas sa provenance. Acceptée par les sites qui demandent une
  attestation mais tolèrent l'auto-attestation (vérifié sur webauthn.io en mode Direct).

Les sites qui vérifient une chaîne de certificats fabricant (AAGUID connu via la FIDO
Metadata Service) refuseront : c'est voulu par FIDO2 et non contournable sans être un
authentificateur certifié disposant d'une clé d'attestation fabricant. Pour ces sites,
le bouton « Utiliser un autre appareil » permet d'utiliser une vraie clé matérielle.

## Limites connues

1. Création/utilisation d'une passkey : nécessite l'app desktop ouverte et déverrouillée
   (sinon la création est refusée par une erreur standard, voir « Coffre indisponible »).
2. Sites exigeant une attestation matérielle certifiée : non supportés (par conception FIDO2).
3. L'objet renvoyé est conforme en structure mais n'est pas une instance réelle de
   `PublicKeyCredential` ; un site testant `instanceof` strictement pourrait le refuser.
4. Seule l'extension enrichie gère les passkeys.
5. La fenêtre de consentement vit dans la page : les contrôles anti-clickjacking ci-dessus
   réduisent fortement le risque mais ne valent pas une surface appartenant à l'extension
   (fenêtre `chrome.windows.create` de type popup pilotée par le service worker), que la page
   ne pourrait ni styler ni recouvrir ; c'est l'évolution prévue. Effet de bord : sur une page
   qui applique elle-même un filtre ou une opacité à `<html>` (mode « deuil » en niveaux de
   gris, certains modes sombres par filtre), les boutons de signature restent bloqués et un
   avertissement invite à utiliser « Utiliser un autre appareil ».
6. Autofill de passkeys (médiation « conditional ») : non proposé par RDVAULT, laissé au
   navigateur ; l'utilisateur passe par le bouton de connexion par passkey du site.
7. Liste des suffixes publics partielle (voir « Cas laissés au navigateur »).
8. **ES256 seulement.** RDVAULT ne produit que des clés ES256 (P-256, `alg: -7`). Si
   `pubKeyCredParams` ne contient pas `-7` (par exemple RS256 seul), la création est laissée au
   navigateur ; liste absente ou vide = valeurs par défaut de la spécification (ES256 inclus).
9. **Iframe aux ancêtres inconnus.** Dans une iframe, `clientDataJSON` doit indiquer
   `crossOrigin` et, le cas échéant, `topOrigin` (origine de la page principale). Quand les
   origines des ancêtres sont inconnues (`location.ancestorOrigins` absent, ou origine masquée
   `null`), RDVAULT ne peut pas les remplir : la cérémonie est renvoyée au navigateur. Une iframe
   d'une autre origine, déléguée par `allow="publickey-credentials-…"`, reçoit `crossOrigin: true`
   et `topOrigin`.
10. **Vérification de l'utilisateur = déverrouillage du coffre.** RDVAULT ne redemande ni PIN, ni
    biométrie, ni mot de passe maître au moment de la cérémonie : le drapeau UV atteste que le
    coffre a été déverrouillé par le mot de passe maître (voir « Vérification de l'utilisateur »).
    Une personne qui a accès à la session Windows pendant que RDVAULT est déverrouillé peut donc
    utiliser les passkeys, comme les mots de passe du coffre ; l'expiration de la session RDVAULT
    (15 min sans activité dans l'application, 3 h de poste verrouillé) referme le coffre et limite
    cette fenêtre.
11. **Mode HashiCorp Vault : historique du blob.** Les versions antérieures de `.rdvault-passkeys`,
    avec la clé privée des passkeys supprimées, restent lisibles avec le droit de lecture du coffre
    tant que `max_versions` les garde (voir « Stockage »). Le coffre local, lui, ne garde que la
    dernière version.
