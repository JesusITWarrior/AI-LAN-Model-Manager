#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory=$true)][ValidateSet('controller','agent')][string]$Role,
  [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$')][string]$Version='0.0.0',
  [ValidateSet('Install','Upgrade','Uninstall')][string]$Action='Install',
  [switch]$Activate,
  [string]$ControllerUrl,
  [string]$CaCertificatePath,
  [string]$CaFingerprint,
  [string]$CandidateAddress,
  [int]$AdvertisedPort,
  [string]$DisplayName,
  [switch]$ReEnroll,
  [switch]$Purge
)
$ErrorActionPreference='Stop'
$base=Join-Path $env:ProgramFiles 'LANModelManager';$data=Join-Path $env:ProgramData 'LANModelManager'
$name=if($Role -eq 'agent'){'LANModelAgent'}else{'LANModelController'}
$state=Join-Path $data "state\$Role";$config=Join-Path $data "config\$Role"
$binary=Join-Path $base "releases\$Role\$Version\bin\lan-model-$Role.exe"
# Uninstall intentionally precedes agent configuration construction: removal of
# a damaged installation must never require obsolete enrollment arguments.
if($Action -eq 'Uninstall'){
  $service=Get-Service -Name $name -ErrorAction SilentlyContinue
  if($service -and $PSCmdlet.ShouldProcess($name,'Remove disabled service')){if($service.Status -ne 'Stopped'){throw 'ERR_SERVICE_RUNNING'};& sc.exe delete $name|Out-Null;if($LASTEXITCODE -ne 0){throw 'ERR_SERVICE_DELETE'}}
  if($Purge){foreach($path in @($state,$config)){if($PSCmdlet.ShouldProcess($path,'Purge state or configuration')){Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue}}}
  return
}
function Test-CanonicalIPv4([string]$Value){$parts=$Value.Split('.');if($parts.Count-ne 4){return $false};foreach($part in $parts){if($part-notmatch '^(0|[1-9][0-9]{0,2})$'){return $false};if([int]$part-gt 255){return $false}};return $true}
function Test-PrivateIPv4([string]$Value){if(-not(Test-CanonicalIPv4 $Value)){return $false};$p=$Value.Split('.')|ForEach-Object{[int]$_};return $p[0]-eq 10-or($p[0]-eq 172-and$p[1]-ge 16-and$p[1]-le 31)-or($p[0]-eq 192-and$p[1]-eq 168)}
function Test-RegularFile([string]$Path){if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){return $false};return -not((Get-Item -LiteralPath $Path -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)}
function Assert-SafePath([string]$Path,[switch]$AllowLeafFile){$full=[IO.Path]::GetFullPath($Path);$current=$full;$leaf=$true;while($current){if(Test-Path -LiteralPath $current){$item=Get-Item -LiteralPath $current -Force;if($item.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'ERR_INSTALL_PATH'};if(-not$item.PSIsContainer-and-not($leaf-and$AllowLeafFile)){throw 'ERR_INSTALL_PATH'}};$parent=Split-Path -Parent $current;if($parent-eq$current){break};$current=$parent;$leaf=$false}}
function Restore-AtomicBytes([string]$Path,[byte[]]$Bytes){$temporary="$Path.rollback-$([Guid]::NewGuid().ToString('N'))";[IO.File]::WriteAllBytes($temporary,$Bytes);Move-Item -LiteralPath $temporary -Destination $Path -Force}
if($Role -eq 'agent'){
  $uri=$null;if(-not[Uri]::TryCreate($ControllerUrl,[UriKind]::Absolute,[ref]$uri)-or$uri.Scheme-ne'https'-or-not(Test-PrivateIPv4 $uri.Host)-or$uri.AbsolutePath-ne'/'-or$uri.Query-or$uri.Fragment-or$uri.UserInfo-or$uri.Port-lt 1-or$uri.Port-gt 65535){throw 'ERR_INSTALL_AGENT_CONFIG'}
  if(-not(Test-RegularFile $CaCertificatePath)-or$CaFingerprint-cnotmatch'^[a-f0-9]{64}$'-or-not(Test-PrivateIPv4 $CandidateAddress)-or$AdvertisedPort-lt 1-or$AdvertisedPort-gt 65535-or$AdvertisedPort-in@(7340,7341)-or[string]::IsNullOrWhiteSpace($DisplayName)-or$DisplayName.Length-gt 128-or$DisplayName-ne$DisplayName.Trim()-or$DisplayName-match'[\x00-\x1f\x7f]'){throw 'ERR_INSTALL_AGENT_CONFIG'}
  try{$caObject=New-Object Security.Cryptography.X509Certificates.X509Certificate2($CaCertificatePath);$basic=@($caObject.Extensions|Where-Object{$_.Oid.Value -eq '2.5.29.19'});if($basic.Count -ne 1){throw 0};$decoded=New-Object Security.Cryptography.X509Certificates.X509BasicConstraintsExtension;$decoded.CopyFrom($basic[0]);if(-not $decoded.CertificateAuthority){throw 0};$sha=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($sha.ComputeHash($caObject.RawData))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};if($actual-ne$CaFingerprint){throw 0}}catch{throw 'ERR_INSTALL_AGENT_CONFIG'}
}
if(-not $WhatIfPreference -and -not (Test-Path -LiteralPath $binary -PathType Leaf)){throw 'ERR_INSTALL_BINARY'}
if(-not $WhatIfPreference -and -not (Test-RegularFile $binary)){throw 'ERR_INSTALL_BINARY'}
$caTarget=Join-Path $config 'controller-ca.pem';$reenrollMarker=Join-Path $state 'reenroll.request';$serviceKey="HKLM:\SYSTEM\CurrentControlSet\Services\$name"
foreach($path in @($base,$data,$state,$config)){Assert-SafePath $path};Assert-SafePath $binary -AllowLeafFile;Assert-SafePath $caTarget -AllowLeafFile;Assert-SafePath $reenrollMarker -AllowLeafFile;if($Role-eq'agent'){Assert-SafePath $CaCertificatePath -AllowLeafFile}
$existing=Get-Service -Name $name -ErrorAction SilentlyContinue;$createdService=$false
$createdDirectories=New-Object Collections.Generic.List[string];$oldDirectoryAcls=@{}
$oldCim=if($existing){Get-CimInstance Win32_Service -Filter "Name='$name'"}else{$null};$oldStatus=if($existing){$existing.Status}else{$null}
if($existing){$expectedAccount="NT SERVICE\$name";$releasePattern='^"'+[Regex]::Escape((Join-Path $base "releases\$Role\"))+'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\\bin\\'+[Regex]::Escape("lan-model-$Role.exe")+'"$';if($existing.Status-ne'Stopped'-or$null-eq$oldCim-or$oldCim.StartName-ine$expectedAccount-or$oldCim.PathName-cnotmatch$releasePattern){throw 'ERR_INSTALL_SERVICE_OWNERSHIP'}}
$oldEnvironment=$null;$hadEnvironment=$false;if(Test-Path $serviceKey){$property=Get-ItemProperty -Path $serviceKey -Name Environment -ErrorAction SilentlyContinue;if($null-ne$property){$oldEnvironment=@($property.Environment);$hadEnvironment=$true}}
$oldCa=$null;$hadCa=Test-Path -LiteralPath $caTarget -PathType Leaf;if($hadCa){if(-not(Test-RegularFile $caTarget)){throw 'ERR_INSTALL_AGENT_CONFIG'};$oldCa=[IO.File]::ReadAllBytes($caTarget)}
$hadReEnrollMarker=Test-Path -LiteralPath $reenrollMarker -PathType Leaf;$oldReEnrollMarker=if($hadReEnrollMarker){[IO.File]::ReadAllBytes($reenrollMarker)}else{$null}
$serviceEnvironment=if($Role -eq 'agent'){@("LANMM_STATE_DIR=$state","LANMM_CERT_DIR=$(Join-Path $state 'cert')","LANMM_CACHE_DIR=$(Join-Path $state 'cache')","LANMM_ENROLLMENT_CONTROLLER_URL=$ControllerUrl","LANMM_ENROLLMENT_CA_CERT_FILE=$caTarget","LANMM_ENROLLMENT_CA_FINGERPRINT_SHA256=$CaFingerprint","LANMM_ENROLLMENT_CANDIDATE_ADDRESS=$CandidateAddress","LANMM_ENROLLMENT_CANDIDATE_PORT=$AdvertisedPort","LANMM_ENROLLMENT_PROTOCOL_MAJOR=1","LANMM_ENROLLMENT_PROTOCOL_MINOR=0","LANMM_DISCOVERY_DISPLAY_NAME=$DisplayName","LANMM_DISCOVERY_ADDRESS=$CandidateAddress","LANMM_DISCOVERY_PORT=$AdvertisedPort","LANMM_DISCOVERY_TTL_SECONDS=120","LANMM_OLLAMA_ENDPOINT=http://127.0.0.1:11434")}else{@("LANMM_DATA_DIR=$state")}
try{
  if(-not$existing){if($PSCmdlet.ShouldProcess($name,'Create disabled service')){New-Service -Name $name -BinaryPathName ('"{0}"'-f$binary) -StartupType Disabled -Description "LAN Model Manager $Role"|Out-Null;$createdService=$true;& sc.exe config $name obj= "NT SERVICE\$name"|Out-Null;if($LASTEXITCODE-ne 0){throw 'ERR_SERVICE_ACCOUNT'}}}
  elseif($PSCmdlet.ShouldProcess($name,'Stage service binary path')){if($existing.Status-ne'Stopped'){throw 'ERR_SERVICE_RUNNING'};& sc.exe config $name binPath= ('"{0}"'-f$binary) start= disabled obj= "NT SERVICE\$name"|Out-Null;if($LASTEXITCODE-ne 0){throw 'ERR_SERVICE_CONFIG'}}
  foreach($path in @($state,$config)){if($PSCmdlet.ShouldProcess($path,'Create protected directory')){if(Test-Path -LiteralPath $path){$item=Get-Item -LiteralPath $path -Force;if(-not$item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'ERR_SERVICE_ACL'};$oldDirectoryAcls[$path]=Get-Acl -LiteralPath $path}else{New-Item -ItemType Directory -Path $path -Force|Out-Null;$createdDirectories.Add($path)};& icacls.exe $path /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "NT SERVICE\${name}:(OI)(CI)M"|Out-Null;if($LASTEXITCODE-ne 0){throw 'ERR_SERVICE_ACL'}}}
  if($Role-eq'agent'-and$PSCmdlet.ShouldProcess($caTarget,'Atomically install public controller CA certificate')){$caTemp=Join-Path $config ('.controller-ca-'+[Guid]::NewGuid().ToString('N')+'.tmp');Copy-Item -LiteralPath $CaCertificatePath -Destination $caTemp -Force;Move-Item -LiteralPath $caTemp -Destination $caTarget -Force}
  if($Role-eq'agent'-and$ReEnroll-and$PSCmdlet.ShouldProcess($reenrollMarker,'Request owner-confirmed re-enrollment')){$markerTemp="$reenrollMarker.$([Guid]::NewGuid().ToString('N')).tmp";[IO.File]::WriteAllText($markerTemp,"owner-authorized-reenroll`n",(New-Object Text.UTF8Encoding($false)));Move-Item -LiteralPath $markerTemp -Destination $reenrollMarker -Force}
  if($PSCmdlet.ShouldProcess($serviceKey,'Set bounded service environment')){New-ItemProperty -Path $serviceKey -Name Environment -PropertyType MultiString -Value $serviceEnvironment -Force|Out-Null}
  if($Activate-and$PSCmdlet.ShouldProcess($name,'Activate and health-check service')){& sc.exe config $name start= demand|Out-Null;if($LASTEXITCODE-ne 0){throw 'ERR_SERVICE_CONFIG'};Start-Service -Name $name;(Get-Service -Name $name).WaitForStatus('Running',[TimeSpan]::FromSeconds(15));if((Get-Service -Name $name).Status-ne'Running'){throw 'ERR_INSTALL_HEALTH'}}
}catch{
  $rollbackFailed=$false
  foreach($temporary in @($caTemp,$markerTemp)){if($temporary-and(Test-Path -LiteralPath $temporary)){try{Remove-Item -LiteralPath $temporary -Force -ErrorAction Stop}catch{$rollbackFailed=$true}}}
  $rollbackService=Get-Service -Name $name -ErrorAction SilentlyContinue;if($rollbackService-and$rollbackService.Status-ne'Stopped'){try{Stop-Service -Name $name -Force -ErrorAction Stop}catch{$rollbackFailed=$true}}
  if($createdService){& sc.exe delete $name|Out-Null;if($LASTEXITCODE-ne 0){$rollbackFailed=$true}}
  else{
    if($oldCim){$start=if($oldCim.StartMode-eq'Auto'){'auto'}elseif($oldCim.StartMode-eq'Disabled'){'disabled'}else{'demand'};& sc.exe config $name binPath= $oldCim.PathName start= $start obj= $oldCim.StartName|Out-Null;if($LASTEXITCODE-ne 0){$rollbackFailed=$true}}
    try{if($hadEnvironment){New-ItemProperty -Path $serviceKey -Name Environment -PropertyType MultiString -Value $oldEnvironment -Force -ErrorAction Stop|Out-Null}else{Remove-ItemProperty -Path $serviceKey -Name Environment -ErrorAction SilentlyContinue;if($null-ne(Get-ItemProperty -Path $serviceKey -Name Environment -ErrorAction SilentlyContinue)){throw 0}}}catch{$rollbackFailed=$true}
  }
  if($Role-eq'agent'){try{if($hadCa){Restore-AtomicBytes $caTarget $oldCa}else{if(Test-Path -LiteralPath $caTarget){Remove-Item -LiteralPath $caTarget -Force -ErrorAction Stop}};if($hadReEnrollMarker){Restore-AtomicBytes $reenrollMarker $oldReEnrollMarker}else{Remove-Item -LiteralPath $reenrollMarker -Force -ErrorAction SilentlyContinue;if(Test-Path -LiteralPath $reenrollMarker){throw 0}}}catch{$rollbackFailed=$true}}
  foreach($entry in $oldDirectoryAcls.GetEnumerator()){try{Set-Acl -LiteralPath $entry.Key -AclObject $entry.Value -ErrorAction Stop}catch{$rollbackFailed=$true}}
  foreach($path in @($createdDirectories)|Sort-Object Length -Descending){try{$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if(-not$item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or@(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop).Count-ne 0){throw 0};Remove-Item -LiteralPath $path -Force -ErrorAction Stop}catch{$rollbackFailed=$true}}
  if(-not$createdService-and$oldStatus-eq'Running'-and-not$rollbackFailed){try{Start-Service -Name $name -ErrorAction Stop}catch{$rollbackFailed=$true}}
  if($rollbackFailed){throw 'ERR_INSTALL_ROLLBACK_FAILED'}
  throw 'ERR_UPGRADE_ROLLBACK'
}
# Without -Activate the service remains disabled and stopped. No firewall rule is altered.
