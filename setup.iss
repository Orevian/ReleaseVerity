; ReleaseVerity installer (Inno Setup 6).
;
; Build with:   scripts\build.ps1 -Target installer
; The build script passes every define below, so nothing here depends on a fixed path:
;   AppVersion  product version (single source of truth: [workspace.package] in Cargo.toml)
;   SourceDir   the assembled portable/onedir folder (dist\portable\ReleaseVerity)
;   OutputDir   where ReleaseVerity-Setup-x64.exe is written
;   IconFile    the project's icon.ico, used unmodified
; Running ISCC.exe by hand also works: the fallbacks below are relative to this file.

#ifndef AppVersion
  #error AppVersion is not defined. Build with scripts\build.ps1 -Target installer (the version comes from Cargo.toml).
#endif
#ifndef SourceDir
  #define SourceDir "dist\portable\ReleaseVerity"
#endif
#ifndef OutputDir
  #define OutputDir "dist\installer"
#endif
#ifndef IconFile
  #define IconFile "icon.ico"
#endif

#define AppName      "ReleaseVerity"
#define AppPublisher "ReleaseVerity contributors"
#define AppURL       "https://github.com/Orevian/ReleaseVerity"
#define AppExeName   "ReleaseVerity.exe"

[Setup]
AppId={{6F1D2C5A-3B7E-4F5B-9A0C-5C0E1B7A9D42}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases
VersionInfoVersion={#AppVersion}.0
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} Setup
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\resources\icon.ico
SetupIconFile={#IconFile}
OutputDir={#OutputDir}
OutputBaseFilename=ReleaseVerity-Setup-x64
LicenseFile=LICENSE
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
ChangesEnvironment=yes
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"

[CustomMessages]
english.AddToPath=Add the "releaseverity" command line tool to PATH
turkish.AddToPath="releaseverity" komut satırı aracını PATH'e ekle

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addtopath"; Description: "{cm:AddToPath}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; `config` and `data` are excluded on purpose: a `config` folder next to the exe switches ReleaseVerity
; into portable mode, which an installed copy under Program Files must never be in.
Source: "{#SourceDir}\*"; DestDir: "{app}"; Excludes: "config,data"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\resources\icon.ico"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\resources\icon.ico"; Tasks: desktopicon

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}\cli"; Tasks: addtopath; Check: NeedsAddPath(ExpandConstant('{app}\cli'))

[Run]
; Offered after an interactive install; never launched by a silent install (ShipCheck installs silently).
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[Code]
const
  EnvKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE, EnvKey, 'Path', OrigPath) then
  begin
    Result := True;
    Exit;
  end;
  Result := Pos(';' + Lowercase(Param) + ';', ';' + Lowercase(OrigPath) + ';') = 0;
end;

procedure RemoveFromPath(Entry: string);
var
  Paths, Padded: string;
  P: Integer;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE, EnvKey, 'Path', Paths) then
    Exit;
  Padded := ';' + Paths + ';';
  P := Pos(';' + Uppercase(Entry) + ';', Uppercase(Padded));
  if P = 0 then
    Exit;
  Delete(Padded, P, Length(Entry) + 1);
  if Length(Padded) <= 2 then
    Paths := ''
  else
    Paths := Copy(Padded, 2, Length(Padded) - 2);
  RegWriteExpandStringValue(HKEY_LOCAL_MACHINE, EnvKey, 'Path', Paths);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}\cli'));
end;
