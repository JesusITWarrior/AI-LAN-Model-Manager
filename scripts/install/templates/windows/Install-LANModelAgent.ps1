#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory=$true)][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$')][string]$Version,
  [Parameter(Mandatory=$true)][string]$ControllerUrl,
  [Parameter(Mandatory=$true)][string]$CaCertificatePath,
  [Parameter(Mandatory=$true)][string]$CaFingerprint,
  [Parameter(Mandatory=$true)][string]$CandidateAddress,
  [Parameter(Mandatory=$true)][int]$AdvertisedPort,
  [string]$DisplayName=$env:COMPUTERNAME,
  [switch]$ReEnroll,
  [switch]$Activate
)
$ErrorActionPreference='Stop'
function Test-CanonicalIPv4([string]$Value){$parts=$Value.Split('.');if($parts.Count-ne 4){return $false};foreach($part in $parts){if($part-notmatch'^(0|[1-9][0-9]{0,2})$'-or[int]$part-gt 255){return $false}};return $true}
function Test-PrivateIPv4([string]$Value){if(-not(Test-CanonicalIPv4 $Value)){return $false};$p=$Value.Split('.')|ForEach-Object{[int]$_};return $p[0]-eq 10-or($p[0]-eq 172-and$p[1]-ge 16-and$p[1]-le 31)-or($p[0]-eq 192-and$p[1]-eq 168)}
function Assert-SafePath([string]$Path,[switch]$AllowLeafFile){$full=[IO.Path]::GetFullPath($Path);$current=$full;$leaf=$true;while($current){if(Test-Path -LiteralPath $current){$item=Get-Item -LiteralPath $current -Force;if($item.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'ERR_INSTALL_PATH'};if(-not$item.PSIsContainer-and-not($leaf-and$AllowLeafFile)){throw 'ERR_INSTALL_PATH'}};$parent=Split-Path -Parent $current;if($parent-eq$current){break};$current=$parent;$leaf=$false}}
$uri=$null;if(-not[Uri]::TryCreate($ControllerUrl,[UriKind]::Absolute,[ref]$uri)-or$uri.Scheme-ne'https'-or-not(Test-PrivateIPv4 $uri.Host)-or$uri.AbsolutePath-ne'/'-or$uri.Query-or$uri.Fragment-or$uri.UserInfo-or$uri.Port-lt 1-or$uri.Port-gt 65535-or$CaFingerprint-cnotmatch'^[a-f0-9]{64}$'-or-not(Test-PrivateIPv4 $CandidateAddress)-or$AdvertisedPort-lt 1-or$AdvertisedPort-gt 65535-or$AdvertisedPort-in@(7340,7341)-or[string]::IsNullOrWhiteSpace($DisplayName)-or$DisplayName.Length-gt 128-or$DisplayName-ne$DisplayName.Trim()-or$DisplayName-match'[\x00-\x1f\x7f]'){throw 'ERR_INSTALL_AGENT_CONFIG'}
$caItem=Get-Item -LiteralPath $CaCertificatePath -Force -ErrorAction SilentlyContinue;if($null-eq$caItem-or$caItem.PSIsContainer-or($caItem.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'ERR_INSTALL_AGENT_CONFIG'}
$packageRoot=Split-Path -Parent $PSScriptRoot;$manifest=Join-Path $PSScriptRoot 'install-manifest.json';$runtime=Join-Path $PSScriptRoot 'cli.js';$serviceScript=Join-Path $PSScriptRoot 'Install-LANModelService.ps1'
foreach($path in @($manifest,$runtime,$serviceScript,(Join-Path $packageRoot 'bin\lan-model-agent.exe'))){if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw 'ERR_INSTALL_PACKAGE'}}
$node=(Get-Command node.exe -ErrorAction SilentlyContinue).Source;if(-not$node){throw 'ERR_INSTALL_NODE'}
$pointer=Join-Path $env:ProgramFiles 'LANModelManager\agent.current';$data=Join-Path $env:ProgramData 'LANModelManager';$state=Join-Path $data 'state\agent';$config=Join-Path $data 'config\agent';$directorySnapshots=@()
Assert-SafePath $pointer -AllowLeafFile;Assert-SafePath $CaCertificatePath -AllowLeafFile;foreach($path in @($data,$state,$config)){Assert-SafePath $path}
$hadPointer=Test-Path -LiteralPath $pointer -PathType Leaf;$oldPointer=if($hadPointer){[IO.File]::ReadAllBytes($pointer)}else{$null}
foreach($path in @($state,$config)){$existed=Test-Path -LiteralPath $path;if($existed){$item=Get-Item -LiteralPath $path -Force;if(-not$item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'ERR_INSTALL_PATH'};$acl=Get-Acl -LiteralPath $path}else{$acl=$null};$directorySnapshots+=New-Object PSObject -Property @{Path=$path;Existed=$existed;Acl=$acl}}
$action=if($hadPointer){'upgrade'}else{'install'};$serviceAction=if($action-eq'upgrade'){'Upgrade'}else{'Install'}
$args=@($runtime,$action,'--platform','windows','--payload',$packageRoot,'--manifest',$manifest,'--role','agent')
$serviceArgs=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$serviceScript,'-Role','agent','-Version',$Version,'-Action',$serviceAction,'-ControllerUrl',$ControllerUrl,'-CaCertificatePath',$CaCertificatePath,'-CaFingerprint',$CaFingerprint,'-CandidateAddress',$CandidateAddress,'-AdvertisedPort',$AdvertisedPort,'-DisplayName',$DisplayName);if($ReEnroll){$serviceArgs+='-ReEnroll'};if($Activate){$serviceArgs+='-Activate'}
if($WhatIfPreference){$args+='--dry-run';$serviceArgs+='-WhatIf';&$node @args;if($LASTEXITCODE-ne 0){throw 'ERR_INSTALL_STAGE'};&powershell.exe @serviceArgs;if($LASTEXITCODE-ne 0){throw 'ERR_INSTALL_SERVICE'};return}
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());if(-not$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ERR_INSTALL_ADMIN'}
if($PSCmdlet.ShouldProcess('LAN Model Manager Agent',"$serviceAction verified package $Version")){
  try{
    &$node @args;if($LASTEXITCODE-ne 0){throw 'ERR_INSTALL_STAGE'}
    &powershell.exe @serviceArgs;if($LASTEXITCODE-ne 0){throw 'ERR_INSTALL_SERVICE'}
  }catch{
    $rollbackFailed=$false
    try{if($hadPointer){$temp="$pointer.rollback-$([Guid]::NewGuid().ToString('N'))";[IO.File]::WriteAllBytes($temp,$oldPointer);Move-Item -LiteralPath $temp -Destination $pointer -Force}else{if(Test-Path -LiteralPath $pointer){Remove-Item -LiteralPath $pointer -Force -ErrorAction Stop}}}catch{$rollbackFailed=$true}
    foreach($snapshot in $directorySnapshots){try{if($snapshot.Existed){$item=Get-Item -LiteralPath $snapshot.Path -Force -ErrorAction Stop;if(-not$item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 0};Set-Acl -LiteralPath $snapshot.Path -AclObject $snapshot.Acl -ErrorAction Stop}elseif(Test-Path -LiteralPath $snapshot.Path){$item=Get-Item -LiteralPath $snapshot.Path -Force -ErrorAction Stop;if(-not$item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 0};Remove-Item -LiteralPath $snapshot.Path -Recurse -Force -ErrorAction Stop}}catch{$rollbackFailed=$true}}
    if($rollbackFailed){throw 'ERR_INSTALL_ROLLBACK_FAILED'}
    throw 'ERR_INSTALL_TRANSACTION'
  }
}
