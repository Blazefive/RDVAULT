; ========================================
; RDVAULT - Custom NSIS Installer Script
; ========================================
; DEUX MODES D'INSTALLATION:
; 1. MODE INTERACTIF: Page de selection du mode + configuration
; 2. MODE SILENCIEUX: RDVault-Setup.exe /S /CONFIG=C:\chemin\config.cfg

; ========================================
; VARIABLES
; ========================================
Var VAULT_URL
Var LDAP_AUTH_PATH
Var TRUSTED_DOMAINS
Var RBI_PROXY_URL
Var APP_MODE
Var CONFIG_FILE_PATH
Var TEMP_LINE
Var TEMP_PREFIX
Var hCtl_VaultUrl
Var hCtl_LdapPath
Var hCtl_TrustedDomains
Var hCtl_RbiProxyUrl
Var hCtl_RadioEnterprise
Var hCtl_RadioLocal

; ========================================
; VALEURS PAR DEFAUT
; ========================================
!define DEFAULT_VAULT_URL "https://vault.example.com:8200"
!define DEFAULT_LDAP_PATH "auth/ldap"
!define DEFAULT_TRUSTED_DOMAINS "vault.example.com,localhost,127.0.0.1"
!define DEFAULT_RBI_PROXY_URL ""

!include "FileFunc.nsh"
!include "TextFunc.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"

!macro customHeader
!macroend

!macro preInit
  StrCpy $VAULT_URL "${DEFAULT_VAULT_URL}"
  StrCpy $LDAP_AUTH_PATH "${DEFAULT_LDAP_PATH}"
  StrCpy $TRUSTED_DOMAINS "${DEFAULT_TRUSTED_DOMAINS}"
  StrCpy $RBI_PROXY_URL "${DEFAULT_RBI_PROXY_URL}"
  StrCpy $APP_MODE "enterprise"
  StrCpy $CONFIG_FILE_PATH ""

  ${GetParameters} $0
  ClearErrors
  ${GetOptions} $0 "/CONFIG=" $CONFIG_FILE_PATH

  ; Support /MODE=local en silencieux
  ClearErrors
  ${GetOptions} $0 "/MODE=" $APP_MODE

  StrCmp $CONFIG_FILE_PATH "" PreInitDone
    IfFileExists $CONFIG_FILE_PATH ConfigExists ConfigNotFound

    ConfigExists:
      FileOpen $1 $CONFIG_FILE_PATH r
      IfErrors ConfigNotFound

      ReadLoop:
        FileRead $1 $TEMP_LINE
        IfErrors EndRead
        ${TrimNewLines} $TEMP_LINE $TEMP_LINE
        StrCmp $TEMP_LINE "" ReadLoop
        StrCpy $0 $TEMP_LINE 1
        StrCmp $0 "#" ReadLoop

        StrCpy $TEMP_PREFIX $TEMP_LINE 10
        StrCmp $TEMP_PREFIX "VAULT_URL=" 0 +3
          StrCpy $VAULT_URL $TEMP_LINE "" 10
          Goto ReadLoop

        StrCpy $TEMP_PREFIX $TEMP_LINE 15
        StrCmp $TEMP_PREFIX "LDAP_AUTH_PATH=" 0 +3
          StrCpy $LDAP_AUTH_PATH $TEMP_LINE "" 15
          Goto ReadLoop

        StrCpy $TEMP_PREFIX $TEMP_LINE 16
        StrCmp $TEMP_PREFIX "TRUSTED_DOMAINS=" 0 +3
          StrCpy $TRUSTED_DOMAINS $TEMP_LINE "" 16
          Goto ReadLoop

        StrCpy $TEMP_PREFIX $TEMP_LINE 14
        StrCmp $TEMP_PREFIX "RBI_PROXY_URL=" 0 +3
          StrCpy $RBI_PROXY_URL $TEMP_LINE "" 14
          Goto ReadLoop

        StrCpy $TEMP_PREFIX $TEMP_LINE 9
        StrCmp $TEMP_PREFIX "APP_MODE=" 0 +2
          StrCpy $APP_MODE $TEMP_LINE "" 9
        Goto ReadLoop

      EndRead:
      FileClose $1
      Goto PreInitDone

    ConfigNotFound:
      MessageBox MB_OK|MB_ICONEXCLAMATION "Fichier introuvable: $CONFIG_FILE_PATH"

  PreInitDone:
!macroend

!macro customInit
!macroend

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

  ; Selectionner le mode actuel
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
    StrCpy $APP_MODE "local"
  ${Else}
    StrCpy $APP_MODE "enterprise"
  ${EndIf}
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
FunctionEnd

!macro customInstall
  ; Ecrire config.cfg
  FileOpen $0 "$INSTDIR\config.cfg" w
  FileWrite $0 "# RDVAULT Configuration$\r$\n"
  FileWrite $0 "# Mode: enterprise (serveur Vault) ou local (base locale)$\r$\n"
  FileWrite $0 "APP_MODE=$APP_MODE$\r$\n"

  ; Ecrire les parametres Enterprise uniquement si mode enterprise
  StrCmp $APP_MODE "local" SkipEnterprise
    FileWrite $0 "VAULT_URL=$VAULT_URL$\r$\n"
    FileWrite $0 "LDAP_AUTH_PATH=$LDAP_AUTH_PATH$\r$\n"
    FileWrite $0 "TRUSTED_DOMAINS=$TRUSTED_DOMAINS$\r$\n"
    FileWrite $0 "RBI_PROXY_URL=$RBI_PROXY_URL$\r$\n"
  SkipEnterprise:

  FileClose $0

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
  SetShellVarContext all
  Delete "$DESKTOP\RDVAULT.lnk"
  Delete "$SMPROGRAMS\RDVAULT.lnk"
  SetShellVarContext current
  Delete "$DESKTOP\RDVAULT.lnk"
  Delete "$SMPROGRAMS\RDVAULT.lnk"
  Delete "$INSTDIR\config.cfg"
  Delete "$INSTDIR\config.json"
!macroend
