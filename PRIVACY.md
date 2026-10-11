# Politique de confidentialité — RDVAULT

*Dernière mise à jour : 2026-10-09. À valider par un juriste avant publication.*

RDVAULT est une application de bureau. Par conception, **vos secrets restent sur votre appareil**
(mode local) ou sur le serveur HashiCorp Vault que **vous** contrôlez (mode entreprise).

## Ce que RDVAULT ne fait pas

- ❌ Aucune télémétrie, aucun pistage, aucune analytique tierce intégrée par défaut.
- ❌ Aucun envoi de vos secrets, mots de passe, noms d'utilisateur ou URL à l'éditeur.
- ❌ Aucun compte en ligne obligatoire.

## Données traitées et où elles vont

| Donnée | Emplacement | Transmission externe |
|--------|-------------|----------------------|
| Secrets, mots de passe, TOTP, passkeys | Coffre chiffré local (SQLite) **ou** votre serveur Vault | Aucune vers l'éditeur |
| Mot de passe maître | Jamais stocké (sert à dériver la clé en mémoire) | Jamais |
| Préférences (thème, langue, colonnes) | `localStorage` / fichier de config local | Jamais |
| Journaux | Local, niveau `warn`/`error` en production, URL expurgées des query strings | Jamais |

## Connexions réseau sortantes (toutes optionnelles ou contrôlées par vous)

- **Serveur Vault** : uniquement en mode entreprise, vers l'URL que vous configurez.
- **Vérification de fuite (Have I Been Pwned)** : **uniquement** quand vous cliquez sur « Vérifier les fuites ».
  Transmission en **k-anonymity** : seuls les 5 premiers caractères du SHA-1 d'un mot de passe sont envoyés à `api.pwnedpasswords.com`. Le mot de passe en clair ne quitte jamais l'appareil, et le service ne peut pas savoir lequel vous testez.
- **Connexions que vous lancez vous-même** (SSH ou WinRM via `mvault`, lecture des journaux d'audit Vault par SSH, navigation isolée RBI et son proxy, lanceurs SSH/RDP/SFTP) : uniquement vers les hôtes que vous indiquez ou configurez.
- **Mise à jour automatique** : une fois `electron-updater` activé (voir `docs/PRODUCTION-READINESS.md`), l'application vérifiera la présence d'une nouvelle version auprès du dépôt de distribution, sans transmettre de donnée personnelle. **Dans la version actuelle, aucune requête de mise à jour n'est émise** (le module n'est pas installé).

## Vos droits (RGPD)

Les données étant stockées localement et sous votre contrôle, l'éditeur n'est pas destinataire de vos données personnelles. Vous pouvez supprimer l'intégralité des données en désinstallant l'application et en supprimant le fichier de coffre local.

## Contact

Questions relatives à la confidentialité : `privacy@rdvault.example` *(à remplacer avant publication)*.
