; StegoCrypt Suite Installer Script for NSIS
; ==========================================

!include "MUI2.nsh"
!include "FileFunc.nsh"

; Basic Information
!define PRODUCT_NAME "StegoCrypt Suite"
!define PRODUCT_VERSION "1.0.0"
!define PRODUCT_PUBLISHER "CyberSec Labs"
!define PRODUCT_WEB_SITE "https://cyberseclabs.com"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\stegocrypt_suite.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

; Output and compression
OutFile "dist\StegoCrypt-Suite-Setup.exe"
InstallDir "$PROGRAMFILES64\StegoCrypt Suite"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
SetCompressor lzma
ShowInstDetails show
ShowUninstDetails show
RequestExecutionLevel admin

; Version Information
VIProductVersion "${PRODUCT_VERSION}.0"
VIAddVersionKey "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey "ProductVersion" "${PRODUCT_VERSION}"
VIAddVersionKey "CompanyName" "${PRODUCT_PUBLISHER}"
VIAddVersionKey "FileDescription" "${PRODUCT_NAME} Installer"
VIAddVersionKey "FileVersion" "${PRODUCT_VERSION}"
VIAddVersionKey "LegalCopyright" "© 2024 ${PRODUCT_PUBLISHER}"

; Modern UI Configuration
!define MUI_ABORTWARNING
!define MUI_ICON "assets\icon.ico"
!define MUI_UNICON "assets\icon.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "assets\welcome.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "assets\welcome.bmp"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "assets\license.txt"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\StegoCrypt Suite.bat"
!define MUI_FINISHPAGE_RUN_TEXT "Launch ${PRODUCT_NAME}"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Languages
!insertmacro MUI_LANGUAGE "English"

; Installer Sections
Section "Core Application" SecCore
    SectionIn RO  ; Required section
    
    SetOutPath "$INSTDIR"
    SetOverwrite on
    
    ; Copy all application files
    File /r "build\StegoCryptSuite\*"
    
    ; Create shortcuts
    CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
    CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" "$INSTDIR\StegoCrypt Suite.bat" "" "$INSTDIR\bin\stegocrypt_suite.exe" 0
    CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME} (Console).lnk" "$INSTDIR\StegoCrypt Suite (Console).bat" "" "$INSTDIR\bin\stegocrypt_suite.exe" 0
    CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk" "$INSTDIR\uninst.exe"
    CreateShortCut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\StegoCrypt Suite.bat" "" "$INSTDIR\bin\stegocrypt_suite.exe" 0
    
    ; Register application
    WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\bin\stegocrypt_suite.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\bin\stegocrypt_suite.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
    
    ; Get installation size
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "EstimatedSize" "$0"
    
    WriteUninstaller "$INSTDIR\uninst.exe"
SectionEnd

Section "Visual C++ Redistributable" SecVCRedist
    DetailPrint "Installing Visual C++ Redistributable..."
    
    ; Check if already installed
    ReadRegStr $0 HKLM "SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64" "Version"
    ${If} $0 == ""
        ; Download and install VC++ Redistributable
        NSISdl::download "https://aka.ms/vs/17/release/vc_redist.x64.exe" "$TEMP\vc_redist.x64.exe"
        Pop $R0
        ${If} $R0 == "success"
            ExecWait "$TEMP\vc_redist.x64.exe /quiet /norestart"
            Delete "$TEMP\vc_redist.x64.exe"
        ${Else}
            MessageBox MB_OK "Could not download Visual C++ Redistributable. Please install it manually from Microsoft website."
        ${EndIf}
    ${EndIf}
SectionEnd

Section "File Associations" SecFileAssoc
    ; Register .x25 file extension
    WriteRegStr HKCR ".x25" "" "StegoCryptEncryptedFile"
    WriteRegStr HKCR "StegoCryptEncryptedFile" "" "StegoCrypt Encrypted File"
    WriteRegStr HKCR "StegoCryptEncryptedFile\DefaultIcon" "" "$INSTDIR\bin\stegocrypt_suite.exe,0"
    WriteRegStr HKCR "StegoCryptEncryptedFile\shell\open\command" "" '"$INSTDIR\StegoCrypt Suite.bat" "%1"'
    
    ; Refresh shell
    System::Call 'shell32.dll::SHChangeNotify(i, i, i, i) v (0x08000000, 0, 0, 0)'
SectionEnd

; Section descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
!insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "Core application files (required)"
!insertmacro MUI_DESCRIPTION_TEXT ${SecVCRedist} "Microsoft Visual C++ Redistributable (recommended)"
!insertmacro MUI_DESCRIPTION_TEXT ${SecFileAssoc} "Associate .x25 encrypted files with StegoCrypt Suite"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; Uninstaller Section
Section Uninstall
    ; Remove shortcuts
    Delete "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk"
    Delete "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME} (Console).lnk"
    Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk"
    Delete "$DESKTOP\${PRODUCT_NAME}.lnk"
    RMDir "$SMPROGRAMS\${PRODUCT_NAME}"
    
    ; Remove file associations
    DeleteRegKey HKCR ".x25"
    DeleteRegKey HKCR "StegoCryptEncryptedFile"
    
    ; Remove registry entries
    DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
    DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
    
    ; Remove files and directories
    RMDir /r "$INSTDIR"
    
    SetAutoClose true
SectionEnd

; Functions
Function .onInit
    ; Check Windows version
    ${IfNot} ${AtLeastWin7}
        MessageBox MB_OK "This application requires Windows 7 or later."
        Abort
    ${EndIf}
    
    ; Check for existing installation
    ReadRegStr $R0 ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString"
    ${If} $R0 != ""
        MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION \
            "${PRODUCT_NAME} is already installed. $\n$\nClick 'OK' to remove the previous version or 'Cancel' to cancel this upgrade." \
            /SD IDOK IDOK uninst
        Abort
        
        uninst:
        ClearErrors
        ExecWait '$R0 /S _?=$INSTDIR'
        
        ${If} ${Errors}
            MessageBox MB_OK "Failed to uninstall previous version."
            Abort
        ${EndIf}
        
        Delete $R0
        RMDir $INSTDIR
    ${EndIf}
FunctionEnd