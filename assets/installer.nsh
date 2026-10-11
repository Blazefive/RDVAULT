; ========================================
; RDVAULT - Custom NSIS Installer Script
; ========================================
; DEUX MODES D'INSTALLATION:
; 1. MODE INTERACTIF: Page de selection du mode + configuration
; 2. MODE SILENCIEUX: "RDVAULT Setup x.x.x.exe" /S [/MODE=local|enterprise] [/CONFIG=C:\chemin\config.cfg]
;
; CONFIGURATION ECRITE DANS $INSTDIR\config.cfg :
; - /CONFIG=fichier : copie TELLE QUELLE (toutes les cles, dont TRUSTED_CERT_FINGERPRINTS et LANG) ;
;   electron/configLoader.js valide chaque valeur au demarrage. Un chemin relatif est relatif au
;   dossier de l'installeur. Fichier introuvable en mode silencieux : arret (code 2), rien n'est modifie.
; - /MODE=local|enterprise : ne remplace que la ligne APP_MODE (prioritaire sur le fichier).
;   Valeur invalide en mode silencieux : arret (code 2).
; - Mise a jour : la configuration existante est conservee a l'octet pres. electron-builder lance
;   l'ancien desinstalleur (qui vide $INSTDIR) AVANT customInstall : customInit en garde donc une copie
;   dans $PLUGINSDIR. Seules les valeurs choisies explicitement (/MODE=, pages de l'assistant,
;   pre-remplies avec la configuration existante) remplacent les lignes correspondantes ; les autres
;   lignes (LANG, TRUSTED_CERT_FINGERPRINTS, commentaires...) sont recopiees telles quelles.
; - Premiere installation sans /CONFIG= : fichier genere (valeurs par defaut ou saisies).
;
; ORDRE DES MACROS (electron-builder 26, app-builder-lib/templates/nsis) :
; - .onInit (installer.nsi) : preInit, puis initMultiUser ($INSTDIR = installation existante lue dans
;   le registre, ou /D=), puis customInit ;
; - section (installSection.nsh) : desinstallation de l'ancienne version (son customUnInstall puis
;   RMDir /r $INSTDIR, avec --updated), fichiers de l'application, puis customInstall ;
; - un.install (uninstaller.nsh) : customUnInstall, RMDir /r $INSTDIR, puis DeleteRegKey SHELL_CONTEXT.
; Tests : test/installer/installer-nsis.test.js (banc makensis sur ces macros).

; ========================================
; VARIABLES
; ========================================
Var VAULT_URL
Var LDAP_AUTH_PATH
Var TRUSTED_DOMAINS
Var RBI_PROXY_URL
Var APP_MODE
Var CONFIG_FILE_PATH
Var hCtl_VaultUrl
Var hCtl_LdapPath
Var hCtl_TrustedDomains
Var hCtl_RbiProxyUrl
Var hCtl_RadioEnterprise
Var hCtl_RadioLocal
; "1" si /MODE= a ete fourni (prioritaire sur l'APP_MODE d'un fichier)
Var RDV_MODE_FROM_CLI
; "1" : APP_MODE choisi explicitement (/MODE= ou page de mode) -> remplace la ligne APP_MODE
Var RDV_SET_MODE
; "1" : page entreprise validee -> remplace VAULT_URL, LDAP_AUTH_PATH, TRUSTED_DOMAINS, RBI_PROXY_URL
Var RDV_SET_ENTERPRISE
; Fichier de base (copie de /CONFIG= ou de la configuration existante dans $PLUGINSDIR), ou ""
Var RDV_BASE_CONFIG
; Lecture ligne a ligne (RdvParseLine)
Var RDV_LINE
Var RDV_KEY
Var RDV_VALUE

; ========================================
; VALEURS PAR DEFAUT
; ========================================
; Premiere installation (valeurs proposees dans la page entreprise)
!define DEFAULT_VAULT_URL "https://vault.example.com:8200"
!define DEFAULT_LDAP_PATH "auth/ldap"
!define DEFAULT_TRUSTED_DOMAINS "vault.example.com,localhost,127.0.0.1"
!define DEFAULT_RBI_PROXY_URL ""
; Valeurs appliquees par l'application quand une cle est absente (DEFAULT_CONFIG de electron/configLoader.js)
!define APP_DEFAULT_VAULT_URL "https://vault.example.com:8200"
!define APP_DEFAULT_LDAP_PATH "auth/ldap"
!define APP_DEFAULT_TRUSTED_DOMAINS "localhost,127.0.0.1"
; Copies de travail (dossier temporaire de l'installeur, supprime a la fin)
!define RDV_BASE_COPY "$PLUGINSDIR\rdvault-config.base"
!define RDV_JSON_COPY "$PLUGINSDIR\rdvault-config.json.keep"
!define RDV_PAIRED_COPY "$PLUGINSDIR\rdvault-paired-extensions.json"

!include "FileFunc.nsh"
!include "TextFunc.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"

!macro customHeader
!macroend

; Lecture de la ligne de commande uniquement : les fichiers sont traites dans customInit, une fois
; $INSTDIR positionne sur l'installation existante.
!macro preInit
  StrCpy $VAULT_URL "${DEFAULT_VAULT_URL}"
  StrCpy $LDAP_AUTH_PATH "${DEFAULT_LDAP_PATH}"
  StrCpy $TRUSTED_DOMAINS "${DEFAULT_TRUSTED_DOMAINS}"
  StrCpy $RBI_PROXY_URL "${DEFAULT_RBI_PROXY_URL}"
  StrCpy $APP_MODE "enterprise"
  StrCpy $CONFIG_FILE_PATH ""
  StrCpy $RDV_MODE_FROM_CLI "0"
  StrCpy $RDV_SET_MODE "0"
  StrCpy $RDV_SET_ENTERPRISE "0"
  StrCpy $RDV_BASE_CONFIG ""

  ${GetParameters} $R0
  ; GetOptions positionne le drapeau d'erreur ET vide sa sortie quand l'option est absente : lecture
  ; dans $R1, appliquee seulement si l'option est presente (sinon le defaut serait ecrase).
  ClearErrors
  ${GetOptions} $R0 "/CONFIG=" $R1
  ${IfNot} ${Errors}
    StrCpy $CONFIG_FILE_PATH $R1
  ${EndIf}

  ClearErrors
  ${GetOptions} $R0 "/MODE=" $R1
  ${IfNot} ${Errors}
  ${AndIf} $R1 != ""
    ${If} $R1 == "local"
      StrCpy $APP_MODE "local"
    ${ElseIf} $R1 == "enterprise"
    ${OrIf} $R1 == "entreprise"
      ; "entreprise" (libelle francais de l'assistant) : accepte, comme le faisait la 1.7.0
      StrCpy $APP_MODE "enterprise"
    ${Else}
      MessageBox MB_OK|MB_ICONSTOP "Valeur /MODE= invalide : $R1 (attendu : local ou enterprise)" /SD IDOK
      ${If} ${Silent}
        SetErrorLevel 2
        Quit
      ${EndIf}
      StrCpy $R1 ""
    ${EndIf}
    ${If} $R1 != ""
      StrCpy $RDV_MODE_FROM_CLI "1"
      StrCpy $RDV_SET_MODE "1"
    ${EndIf}
  ${EndIf}
  ClearErrors
!macroend

!macro customInit
  InitPluginsDir

  ; /CONFIG= : copie immediate du fichier fourni (chemin relatif = dossier de l'installeur)
  ${If} $CONFIG_FILE_PATH != ""
    StrCpy $R0 $CONFIG_FILE_PATH 1 1
    StrCpy $R1 $CONFIG_FILE_PATH 1
    ${If} $R0 != ":"
    ${AndIf} $R1 != "\"
    ${AndIf} $R1 != "/"
      StrCpy $CONFIG_FILE_PATH "$EXEDIR\$CONFIG_FILE_PATH"
    ${EndIf}
    ${If} ${FileExists} "$CONFIG_FILE_PATH"
    ${AndIfNot} ${FileExists} "$CONFIG_FILE_PATH\*.*"
      ClearErrors
      CopyFiles /SILENT "$CONFIG_FILE_PATH" "${RDV_BASE_COPY}"
    ${EndIf}
    ${If} ${FileExists} "${RDV_BASE_COPY}"
    ${AndIfNot} ${FileExists} "${RDV_BASE_COPY}\*.*"
      StrCpy $RDV_BASE_CONFIG "${RDV_BASE_COPY}"
    ${Else}
      ; /SD IDOK : ne bloque pas une installation silencieuse (/S), qui s'arrete sans rien modifier
      MessageBox MB_OK|MB_ICONSTOP "Fichier de configuration introuvable ou illisible : $CONFIG_FILE_PATH" /SD IDOK
      ${If} ${Silent}
        SetErrorLevel 2
        Quit
      ${EndIf}
      StrCpy $CONFIG_FILE_PATH ""
    ${EndIf}
  ${EndIf}

  ; Mise a jour : copie de la configuration existante avant que l'ancien desinstalleur ne vide $INSTDIR
  ${If} $RDV_BASE_CONFIG == ""
  ${AndIf} ${FileExists} "$INSTDIR\config.cfg"
    ClearErrors
    CopyFiles /SILENT "$INSTDIR\config.cfg" "${RDV_BASE_COPY}"
    ${If} ${FileExists} "${RDV_BASE_COPY}"
      StrCpy $RDV_BASE_CONFIG "${RDV_BASE_COPY}"
    ${Else}
      MessageBox MB_OK|MB_ICONSTOP "Impossible de sauvegarder la configuration existante ($INSTDIR\config.cfg) : installation interrompue pour ne pas la perdre." /SD IDOK
      SetErrorLevel 2
      Quit
    ${EndIf}
  ${EndIf}

  ; Pages de l'assistant pre-remplies (et page de mode preselectionnee) d'apres cette configuration
  ${If} $RDV_BASE_CONFIG != ""
    Call RdvLoadConfigValues
  ${EndIf}

  ; config.json eventuel (jamais ecrit par l'installeur) : conserve lui aussi
  ${If} ${FileExists} "$INSTDIR\config.json"
    CopyFiles /SILENT "$INSTDIR\config.json" "${RDV_JSON_COPY}"
  ${EndIf}

  ; Appairage des extensions : les desinstalleurs jusqu'a la 1.7.0 le suppriment aussi lors d'une mise
  ; a jour ; copie restauree par customInstall s'il a disparu
  SetShellVarContext current
  ${If} ${FileExists} "$APPDATA\RDVAULT\paired-extensions.json"
    CopyFiles /SILENT "$APPDATA\RDVAULT\paired-extensions.json" "${RDV_PAIRED_COPY}"
  ${EndIf}
  ${If} $installMode == "all"
    SetShellVarContext all
  ${EndIf}
  ClearErrors
!macroend

; ========================================
; OUTILS DE LECTURE / ECRITURE DE config.cfg
; ========================================

; Retire espaces, tabulations, CR et LF aux deux extremites (pile : chaine -> chaine rognee)
Function RdvTrim
  Exch $R0
  Push $R1
  lead:
    StrCpy $R1 $R0 1
    StrCmp $R1 " " cutLead
    StrCmp $R1 "$\t" cutLead
    StrCmp $R1 "$\r" cutLead
    StrCmp $R1 "$\n" cutLead
    Goto trail
  cutLead:
    StrCpy $R0 $R0 "" 1
    Goto lead
  trail:
    StrCpy $R1 $R0 1 -1
    StrCmp $R1 " " cutTrail
    StrCmp $R1 "$\t" cutTrail
    StrCmp $R1 "$\r" cutTrail
    StrCmp $R1 "$\n" cutTrail
    Goto done
  cutTrail:
    StrCpy $R0 $R0 -1
    Goto trail
  done:
  Pop $R1
  Exch $R0
FunctionEnd

; Decoupe $RDV_LINE comme configLoader.parseCfgFile : ligne rognee, vide ou commentaire (#) ignoree,
; cle = texte avant le premier "=" (non vide), valeur = reste, rognes tous deux.
; Sorties : $RDV_KEY (vide si la ligne ne porte pas de cle) et $RDV_VALUE.
Function RdvParseLine
  Push $R0
  Push $R1
  Push $R2
  StrCpy $RDV_KEY ""
  StrCpy $RDV_VALUE ""
  Push $RDV_LINE
  Call RdvTrim
  Pop $R0
  StrCpy $R1 $R0 1
  StrCmp $R1 "#" done
  StrCpy $R2 0
  scan:
    StrCpy $R1 $R0 1 $R2
    StrCmp $R1 "" done
    StrCmp $R1 "=" found
    IntOp $R2 $R2 + 1
    Goto scan
  found:
    IntCmp $R2 0 done
    StrCpy $R1 $R0 $R2
    Push $R1
    Call RdvTrim
    Pop $RDV_KEY
    IntOp $R2 $R2 + 1
    StrCpy $R1 $R0 "" $R2
    Push $R1
    Call RdvTrim
    Pop $RDV_VALUE
  done:
  Pop $R2
  Pop $R1
  Pop $R0
FunctionEnd

; Saute un BOM UTF-8 (EF BB BF) en tete de fichier (configLoader l'ignore aussi) ; sinon revient au
; debut. $R7 = "1" si un BOM a ete saute. Utilise $R7-$R9.
!macro RdvSkipBom HANDLE
  ClearErrors
  FileReadByte ${HANDLE} $R7
  FileReadByte ${HANDLE} $R8
  FileReadByte ${HANDLE} $R9
  ${If} $R7 == "239"
  ${AndIf} $R8 == "187"
  ${AndIf} $R9 == "191"
    StrCpy $R7 "1"
  ${Else}
    FileSeek ${HANDLE} 0 SET
    StrCpy $R7 "0"
  ${EndIf}
  ClearErrors
!macroend

; $R7 = "1" si la chaine lue $RDV_LINE se termine par un saut de ligne LF (seul separateur reconnu par
; configLoader) : la lecture suivante commence alors une nouvelle ligne. Utilise $R7-$R8.
!macro RdvLineEnded
  StrCpy $R7 $RDV_LINE 1 -1
  StrCpy $R8 $RDV_LINE 1 -2
  ${If} $R7 == "$\n"
  ${OrIf} $R8 == "$\n"
    StrCpy $R7 "1"
  ${Else}
    StrCpy $R7 "0"
  ${EndIf}
!macroend

; Pre-remplit les variables de l'assistant depuis $RDV_BASE_CONFIG (la derniere occurrence d'une cle
; l'emporte, comme dans configLoader). Une cle absente prend la valeur que l'application appliquerait.
; APP_MODE n'est pas lu si /MODE= a ete fourni.
Function RdvLoadConfigValues
  Push $R0
  Push $R6
  Push $R7
  Push $R8
  Push $R9
  StrCpy $VAULT_URL "${APP_DEFAULT_VAULT_URL}"
  StrCpy $LDAP_AUTH_PATH "${APP_DEFAULT_LDAP_PATH}"
  StrCpy $TRUSTED_DOMAINS "${APP_DEFAULT_TRUSTED_DOMAINS}"
  StrCpy $RBI_PROXY_URL ""
  ${If} $RDV_MODE_FROM_CLI != "1"
    StrCpy $APP_MODE "enterprise"
  ${EndIf}
  ClearErrors
  FileOpen $R0 "$RDV_BASE_CONFIG" r
  ${IfNot} ${Errors}
    !insertmacro RdvSkipBom $R0
    ; $R6 = "1" quand la lecture commence une ligne (une ligne de plus de 8191 caracteres arrive en
    ; plusieurs morceaux : les suivants ne sont pas des lignes)
    StrCpy $R6 "1"
    ${Do}
      ClearErrors
      FileRead $R0 $RDV_LINE
      ${If} ${Errors}
        ${ExitDo}
      ${EndIf}
      ${If} $R6 == "1"
        Call RdvParseLine
        ${If} $RDV_KEY S== "APP_MODE"
          ${If} $RDV_MODE_FROM_CLI != "1"
            ${If} $RDV_VALUE S== "local"
              StrCpy $APP_MODE "local"
            ${Else}
              StrCpy $APP_MODE "enterprise"
            ${EndIf}
          ${EndIf}
        ${ElseIf} $RDV_KEY S== "VAULT_URL"
          StrCpy $VAULT_URL $RDV_VALUE
        ${ElseIf} $RDV_KEY S== "LDAP_AUTH_PATH"
          StrCpy $LDAP_AUTH_PATH $RDV_VALUE
        ${ElseIf} $RDV_KEY S== "TRUSTED_DOMAINS"
          StrCpy $TRUSTED_DOMAINS $RDV_VALUE
        ${ElseIf} $RDV_KEY S== "RBI_PROXY_URL"
          StrCpy $RBI_PROXY_URL $RDV_VALUE
        ${EndIf}
      ${EndIf}
      !insertmacro RdvLineEnded
      StrCpy $R6 $R7
    ${Loop}
    FileClose $R0
  ${EndIf}
  ClearErrors
  Pop $R9
  Pop $R8
  Pop $R7
  Pop $R6
  Pop $R0
FunctionEnd

; Ajoute une ligne en fin de fichier ($R5 = "1" si la sortie se termine deja par un saut de ligne)
!macro RdvAppendLine HANDLE TEXT
  ${If} $R5 != "1"
    FileWrite ${HANDLE} "$\r$\n"
  ${EndIf}
  FileWrite ${HANDLE} "${TEXT}$\r$\n"
  StrCpy $R5 "1"
!macroend

; Ecrit $INSTDIR\config.cfg a partir de $RDV_BASE_CONFIG en ne remplacant que les cles choisies
; explicitement : APP_MODE si $RDV_SET_MODE, VAULT_URL, LDAP_AUTH_PATH, TRUSTED_DOMAINS et
; RBI_PROXY_URL si $RDV_SET_ENTERPRISE. Toute autre ligne, et toute ligne dont la valeur ne change pas,
; est recopiee a l'octet pres (BOM compris). Une cle choisie absente du fichier est ajoutee en fin de
; fichier, sauf si sa valeur est deja celle que l'application appliquerait.
Function RdvWriteMergedConfig
  ; $R0 source, $R1 cible, $R2/$R3 debut/fin du morceau lu, $R4 "1" = debut de ligne,
  ; $R5 "1" = sortie terminee par un saut de ligne, $R6 nouvelle valeur / octet,
  ; $0 "1" = ligne courante remplacee, $1-$5 cles deja traitees (mode, url, ldap, domaines, rbi)
  Push $R0
  Push $R1
  Push $R2
  Push $R3
  Push $R4
  Push $R5
  Push $R6
  Push $R7
  Push $R8
  Push $R9
  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5
  StrCpy $1 "0"
  StrCpy $2 "0"
  StrCpy $3 "0"
  StrCpy $4 "0"
  StrCpy $5 "0"
  StrCpy $0 "0"
  ClearErrors
  FileOpen $R0 "$RDV_BASE_CONFIG" r
  ${If} ${Errors}
    DetailPrint "config.cfg : lecture de la configuration impossible"
    Goto merge_end
  ${EndIf}
  FileOpen $R1 "$INSTDIR\config.cfg" w
  ${If} ${Errors}
    FileClose $R0
    DetailPrint "config.cfg : ecriture impossible"
    Goto merge_end
  ${EndIf}
  !insertmacro RdvSkipBom $R0
  ${If} $R7 == "1"
    FileWriteByte $R1 239
    FileWriteByte $R1 187
    FileWriteByte $R1 191
  ${EndIf}
  StrCpy $R4 "1"
  StrCpy $R5 "1"
  ${Do}
    FileSeek $R0 0 CUR $R2
    ClearErrors
    FileRead $R0 $RDV_LINE
    ${If} ${Errors}
      ${ExitDo}
    ${EndIf}
    FileSeek $R0 0 CUR $R3
    ${If} $R4 == "1"
      StrCpy $0 "0"
      Call RdvParseLine
      ${If} $RDV_SET_MODE == "1"
      ${AndIf} $RDV_KEY S== "APP_MODE"
        StrCpy $R6 $APP_MODE
        StrCpy $1 "1"
        StrCpy $0 "1"
      ${ElseIf} $RDV_SET_ENTERPRISE == "1"
        ${If} $RDV_KEY S== "VAULT_URL"
          StrCpy $R6 $VAULT_URL
          StrCpy $2 "1"
          StrCpy $0 "1"
        ${ElseIf} $RDV_KEY S== "LDAP_AUTH_PATH"
          StrCpy $R6 $LDAP_AUTH_PATH
          StrCpy $3 "1"
          StrCpy $0 "1"
        ${ElseIf} $RDV_KEY S== "TRUSTED_DOMAINS"
          StrCpy $R6 $TRUSTED_DOMAINS
          StrCpy $4 "1"
          StrCpy $0 "1"
        ${ElseIf} $RDV_KEY S== "RBI_PROXY_URL"
          StrCpy $R6 $RBI_PROXY_URL
          StrCpy $5 "1"
          StrCpy $0 "1"
        ${EndIf}
      ${EndIf}
      ; Valeur inchangee : la ligne d'origine est recopiee telle quelle
      ${If} $0 == "1"
      ${AndIf} $RDV_VALUE S== $R6
        StrCpy $0 "0"
      ${EndIf}
      ${If} $0 == "1"
        FileWrite $R1 "$RDV_KEY=$R6$\r$\n"
        StrCpy $R5 "1"
      ${EndIf}
    ${EndIf}
    ; Recopie a l'octet pres du morceau lu (ignore pour une ligne remplacee et ses morceaux suivants)
    !insertmacro RdvLineEnded
    ${If} $0 != "1"
      FileSeek $R0 $R2 SET
      ${DoWhile} $R2 < $R3
        FileReadByte $R0 $R6
        FileWriteByte $R1 $R6
        IntOp $R2 $R2 + 1
      ${Loop}
      StrCpy $R5 $R7
    ${EndIf}
    StrCpy $R4 $R7
  ${Loop}
  FileClose $R0

  ; Cles choisies absentes du fichier (rien n'est ajoute si la valeur est celle par defaut de l'application)
  ${If} $RDV_SET_MODE == "1"
  ${AndIf} $1 != "1"
  ${AndIf} $APP_MODE S!= "enterprise"
    !insertmacro RdvAppendLine $R1 "APP_MODE=$APP_MODE"
  ${EndIf}
  ${If} $RDV_SET_ENTERPRISE == "1"
    ${If} $2 != "1"
    ${AndIf} $VAULT_URL S!= "${APP_DEFAULT_VAULT_URL}"
      !insertmacro RdvAppendLine $R1 "VAULT_URL=$VAULT_URL"
    ${EndIf}
    ${If} $3 != "1"
    ${AndIf} $LDAP_AUTH_PATH S!= "${APP_DEFAULT_LDAP_PATH}"
      !insertmacro RdvAppendLine $R1 "LDAP_AUTH_PATH=$LDAP_AUTH_PATH"
    ${EndIf}
    ${If} $4 != "1"
    ${AndIf} $TRUSTED_DOMAINS S!= "${APP_DEFAULT_TRUSTED_DOMAINS}"
      !insertmacro RdvAppendLine $R1 "TRUSTED_DOMAINS=$TRUSTED_DOMAINS"
    ${EndIf}
    ${If} $5 != "1"
    ${AndIf} $RBI_PROXY_URL S!= ""
      !insertmacro RdvAppendLine $R1 "RBI_PROXY_URL=$RBI_PROXY_URL"
    ${EndIf}
  ${EndIf}
  FileClose $R1
  merge_end:
  ClearErrors
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
  Pop $R9
  Pop $R8
  Pop $R7
  Pop $R6
  Pop $R5
  Pop $R4
  Pop $R3
  Pop $R2
  Pop $R1
  Pop $R0
FunctionEnd

; Premiere installation sans configuration : fichier genere depuis les valeurs par defaut ou saisies
Function RdvWriteDefaultConfig
  Push $0
  ClearErrors
  FileOpen $0 "$INSTDIR\config.cfg" w
  ${If} ${Errors}
    DetailPrint "config.cfg : ecriture impossible"
  ${Else}
    FileWrite $0 "# RDVAULT Configuration$\r$\n"
    FileWrite $0 "# Mode: enterprise (serveur Vault) ou local (base locale)$\r$\n"
    FileWrite $0 "APP_MODE=$APP_MODE$\r$\n"
    ; Parametres Enterprise uniquement en mode enterprise
    ${If} $APP_MODE != "local"
      FileWrite $0 "VAULT_URL=$VAULT_URL$\r$\n"
      FileWrite $0 "LDAP_AUTH_PATH=$LDAP_AUTH_PATH$\r$\n"
      FileWrite $0 "TRUSTED_DOMAINS=$TRUSTED_DOMAINS$\r$\n"
      FileWrite $0 "RBI_PROXY_URL=$RBI_PROXY_URL$\r$\n"
    ${EndIf}
    FileClose $0
  ${EndIf}
  ClearErrors
  Pop $0
FunctionEnd

; Mode valide dans la page de mode (pile : "local" ou "enterprise") : remplacera APP_MODE
Function RdvModeChosen
  Exch $R0
  StrCpy $APP_MODE $R0
  StrCpy $RDV_SET_MODE "1"
  ; En mode local la page entreprise n'est pas affichee : ses valeurs ne sont pas appliquees
  ${If} $APP_MODE == "local"
    StrCpy $RDV_SET_ENTERPRISE "0"
  ${EndIf}
  Pop $R0
FunctionEnd

; Page entreprise validee : ses valeurs remplaceront les cles correspondantes
Function RdvEnterpriseValidated
  StrCpy $RDV_SET_ENTERPRISE "1"
FunctionEnd

; ========================================
; PAGE 1 : SELECTION DU MODE (Enterprise / Local)
; ========================================
!macro customWelcomePage
  Page custom ModePageCreate ModePageLeave
  Page custom ConfigPageCreate ConfigPageLeave
!macroend

Function ModePageCreate
  IfSilent 0 +2
    Abort

  nsDialogs::Create 1018
  Pop $0
  StrCmp $0 "error" 0 +2
    Abort

  ; Titre
  ${NSD_CreateLabel} 0 0 100% 24u "Bienvenue dans l'installation de RDVAULT"
  Pop $0
  CreateFont $1 "$(^Font)" "12" "700"
  SendMessage $0 ${WM_SETFONT} $1 0

  ${NSD_CreateLabel} 0 30u 100% 16u "Choisissez le mode d'utilisation :"
  Pop $0

  ; Radio Enterprise
  ${NSD_CreateRadioButton} 20u 56u 280u 12u "Mode Entreprise  -  Connexion a un serveur HashiCorp Vault"
  Pop $hCtl_RadioEnterprise
  ${NSD_CreateLabel} 40u 70u 260u 20u "Necessite un serveur Vault, authentification LDAP.$\r$\nPour les equipes et organisations."
  Pop $0

  ; Radio Local
  ${NSD_CreateRadioButton} 20u 100u 280u 12u "Mode Local  -  Base de donnees locale chiffree"
  Pop $hCtl_RadioLocal
  ${NSD_CreateLabel} 40u 114u 260u 20u "Aucun serveur requis, tout est stocke en local.$\r$\nPour un usage personnel ou hors-ligne."
  Pop $0

  ; Selectionner le mode actuel (configuration existante, /CONFIG= ou /MODE=)
  StrCmp $APP_MODE "local" 0 +3
    ${NSD_Check} $hCtl_RadioLocal
    Goto ModeSelected
  ${NSD_Check} $hCtl_RadioEnterprise
  ModeSelected:

  ; Note
  ${NSD_CreateLabel} 0 150u 100% 24u "Ce choix sera ecrit dans le fichier de configuration.$\r$\nVous pourrez le changer en modifiant config.cfg."
  Pop $0

  nsDialogs::Show
FunctionEnd

Function ModePageLeave
  ${NSD_GetState} $hCtl_RadioLocal $0
  ${If} $0 == ${BST_CHECKED}
    Push "local"
  ${Else}
    Push "enterprise"
  ${EndIf}
  Call RdvModeChosen
FunctionEnd

; ========================================
; PAGE 2 : CONFIGURATION ENTREPRISE
; Affichee uniquement en mode Enterprise
; ========================================
Function ConfigPageCreate
  IfSilent 0 +2
    Abort

  ; Skip si mode local
  StrCmp $APP_MODE "local" 0 +2
    Abort

  nsDialogs::Create 1018
  Pop $0
  StrCmp $0 "error" 0 +2
    Abort

  ; Titre
  ${NSD_CreateLabel} 0 0 100% 20u "Configuration du serveur Vault :"
  Pop $0

  ; URL Vault
  ${NSD_CreateLabel} 0 26u 100% 12u "URL du serveur Vault (avec le port) :"
  Pop $0
  ${NSD_CreateText} 0 40u 100% 12u "$VAULT_URL"
  Pop $hCtl_VaultUrl

  ; LDAP Path
  ${NSD_CreateLabel} 0 62u 100% 12u "Chemin d'authentification LDAP :"
  Pop $0
  ${NSD_CreateText} 0 76u 100% 12u "$LDAP_AUTH_PATH"
  Pop $hCtl_LdapPath

  ; Trusted Domains
  ${NSD_CreateLabel} 0 98u 100% 12u "Domaines SSL de confiance (virgules) :"
  Pop $0
  ${NSD_CreateText} 0 112u 100% 12u "$TRUSTED_DOMAINS"
  Pop $hCtl_TrustedDomains

  ; Note
  ${NSD_CreateLabel} 0 130u 100% 12u "Incluez toujours localhost,127.0.0.1"
  Pop $0

  ; RBI Proxy URL
  ${NSD_CreateLabel} 0 150u 100% 12u "URL du proxy RBI (partage de sessions securisees) :"
  Pop $0
  ${NSD_CreateText} 0 164u 100% 12u "$RBI_PROXY_URL"
  Pop $hCtl_RbiProxyUrl

  nsDialogs::Show
FunctionEnd

Function ConfigPageLeave
  ${NSD_GetText} $hCtl_VaultUrl $VAULT_URL
  ${NSD_GetText} $hCtl_LdapPath $LDAP_AUTH_PATH
  ${NSD_GetText} $hCtl_TrustedDomains $TRUSTED_DOMAINS
  ${NSD_GetText} $hCtl_RbiProxyUrl $RBI_PROXY_URL

  StrCmp $VAULT_URL "" 0 +3
    MessageBox MB_OK "URL Vault obligatoire"
    Abort
  StrCmp $LDAP_AUTH_PATH "" 0 +3
    MessageBox MB_OK "Chemin LDAP obligatoire"
    Abort
  StrCmp $TRUSTED_DOMAINS "" 0 +3
    MessageBox MB_OK "Domaines obligatoires"
    Abort
  Call RdvEnterpriseValidated
FunctionEnd

!macro customInstall
  ; Base : /CONFIG= ou configuration existante, copiees par customInit avant que l'ancien desinstalleur
  ; ne vide $INSTDIR ; a defaut, un config.cfg deja present dans le dossier choisi
  ${If} $RDV_BASE_CONFIG == ""
  ${AndIf} ${FileExists} "$INSTDIR\config.cfg"
    ClearErrors
    CopyFiles /SILENT "$INSTDIR\config.cfg" "${RDV_BASE_COPY}"
    ${If} ${FileExists} "${RDV_BASE_COPY}"
      StrCpy $RDV_BASE_CONFIG "${RDV_BASE_COPY}"
    ${EndIf}
  ${EndIf}

  ${If} $RDV_BASE_CONFIG != ""
    ${If} $RDV_SET_MODE == "1"
    ${OrIf} $RDV_SET_ENTERPRISE == "1"
      Call RdvWriteMergedConfig
    ${Else}
      ; Aucun choix explicite : copie a l'identique
      ClearErrors
      CopyFiles /SILENT "$RDV_BASE_CONFIG" "$INSTDIR\config.cfg"
    ${EndIf}
    DetailPrint "config.cfg : configuration existante ou fournie conservee"
  ${Else}
    Call RdvWriteDefaultConfig
  ${EndIf}

  ${If} ${FileExists} "${RDV_JSON_COPY}"
  ${AndIfNot} ${FileExists} "$INSTDIR\config.json"
    CopyFiles /SILENT "${RDV_JSON_COPY}" "$INSTDIR\config.json"
  ${EndIf}

  ; Appairage des extensions supprime par l'ancien desinstalleur (<= 1.7.0) : restaure
  SetShellVarContext current
  ${If} ${FileExists} "${RDV_PAIRED_COPY}"
  ${AndIfNot} ${FileExists} "$APPDATA\RDVAULT\paired-extensions.json"
    CreateDirectory "$APPDATA\RDVAULT"
    CopyFiles /SILENT "${RDV_PAIRED_COPY}" "$APPDATA\RDVAULT\paired-extensions.json"
  ${EndIf}
  ClearErrors

  ; Raccourcis
  ${if} $installMode == "all"
    SetShellVarContext all
  ${else}
    SetShellVarContext current
  ${endIf}
  CreateShortCut "$DESKTOP\RDVAULT.lnk" "$INSTDIR\RDVAULT.exe" "" "$INSTDIR\resources\shortcut-icon.ico" 0
  CreateShortCut "$SMPROGRAMS\RDVAULT.lnk" "$INSTDIR\RDVAULT.exe" "" "$INSTDIR\resources\shortcut-icon.ico" 0
!macroend

!macro customUnInstall
  ; Raccourcis : supprimes aussi lors d'une mise a jour (customInstall les recree)
  SetShellVarContext all
  Delete "$DESKTOP\RDVAULT.lnk"
  Delete "$SMPROGRAMS\RDVAULT.lnk"
  SetShellVarContext current
  Delete "$DESKTOP\RDVAULT.lnk"
  Delete "$SMPROGRAMS\RDVAULT.lnk"

  ; Vraie desinstallation uniquement : electron-builder lance aussi ce desinstalleur, avec --updated,
  ; a chaque mise a jour (installSection.nsh, uninstallOldVersion) ; la configuration et l'appairage
  ; des extensions doivent alors etre conserves.
  ${ifNot} ${isUpdated}
    Delete "$INSTDIR\config.cfg"
    Delete "$INSTDIR\config.json"

    ; Donnees de session dans le profil utilisateur (la base locale chiffree local-vault.db est CONSERVEE)
    SetShellVarContext current
    Delete "$APPDATA\RDVAULT\cli\session.json"
    Delete "$APPDATA\RDVAULT\paired-extensions.json"
    Delete "$APPDATA\RDVAULT\vault-sync.enc"
    Delete "$APPDATA\RDVAULT\vault-sync.json"
    Delete "$APPDATA\RDVAULT\sync-auth-token.txt"
  ${endIf}

  ; Profils Chromium temporaires des sessions RBI (rbi-*) : perimes, l'application est fermee
  FindFirst $0 $1 "$TEMP\rbi-*"
  RbiCleanLoop:
    StrCmp $1 "" RbiCleanDone
    RMDir /r "$TEMP\$1"
    FindNext $0 $1
    Goto RbiCleanLoop
  RbiCleanDone:
  FindClose $0

  ; Contexte de l'installation retabli : electron-builder enchaine avec DeleteRegKey SHELL_CONTEXT, qui
  ; viserait HKCU (au lieu de HKLM pour une installation par machine) si le contexte restait "current"
  ; et laisserait l'entree dans "Applications installees" apres la desinstallation.
  ${if} $installMode == "all"
    SetShellVarContext all
  ${else}
    SetShellVarContext current
  ${endIf}
!macroend
