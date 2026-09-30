#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory=$true)][ValidateSet('controller','agent')][string]$Role,
  [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$')][string]$Version='0.0.0',
  [ValidateSet('Install','Upgrade','Uninstall')][string]$Action='Install',
  [switch]$Activate,
  [switch]$Purge
)
$ErrorActionPreference='Stop'
$base=Join-Path $env:ProgramFiles 'LANModelManager'
$data=Join-Path $env:ProgramData 'LANModelManager'
$name=if($Role -eq 'agent'){'LANModelAgent'}else{'LANModelController'}
$state=Join-Path $data "state\$Role"; $config=Join-Path $data "config\$Role"
$serviceEnvironment=if($Role -eq 'agent'){
  @("LANMM_STATE_DIR=$state","LANMM_CERT_DIR=$(Join-Path $state 'cert')","LANMM_CACHE_DIR=$(Join-Path $state 'cache')")
}else{
  @("LANMM_DATA_DIR=$state")
}
$binary=Join-Path $base "releases\$Role\$Version\bin\lan-model-$Role.exe"
if($Action -eq 'Uninstall') {
  $service=Get-Service -Name $name -ErrorAction SilentlyContinue
  if($service -and $PSCmdlet.ShouldProcess($name,'Remove disabled service')) { if($service.Status -ne 'Stopped'){throw 'ERR_SERVICE_RUNNING'}; & sc.exe delete $name | Out-Null; if($LASTEXITCODE -ne 0){throw 'ERR_SERVICE_DELETE'} }
  if($Purge) { foreach($path in @($state,$config)){if($PSCmdlet.ShouldProcess($path,'Purge state or configuration')){Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue}} }
  return
}
if(-not $WhatIfPreference -and -not (Test-Path -LiteralPath $binary -PathType Leaf)){throw 'ERR_INSTALL_BINARY'}
$oldBinary=$null
$existing=Get-Service -Name $name -ErrorAction SilentlyContinue
if($existing){$oldBinary=(Get-CimInstance Win32_Service -Filter "Name='$name'").PathName}
if(-not $existing) {
  if($PSCmdlet.ShouldProcess($name,'Create disabled service')) {
    New-Service -Name $name -BinaryPathName ('"{0}"' -f $binary) -StartupType Disabled -Description "LAN Model Manager $role" | Out-Null
    & sc.exe config $name obj= "NT SERVICE\$name" | Out-Null
    if($LASTEXITCODE -ne 0){throw 'ERR_SERVICE_ACCOUNT'}
  }
} elseif($PSCmdlet.ShouldProcess($name,'Stage service binary path')) {
  $service=Get-Service -Name $name
  if($service.Status -ne 'Stopped'){throw 'ERR_SERVICE_RUNNING'}
  & sc.exe config $name binPath= ('"{0}"' -f $binary) start= disabled obj= "NT SERVICE\$name" | Out-Null
  if($LASTEXITCODE -ne 0){throw 'ERR_SERVICE_CONFIG'}
}
foreach($path in @($state,$config)){
  if($PSCmdlet.ShouldProcess($path,'Create protected directory')){
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    & icacls.exe $path /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "NT SERVICE\${name}:(OI)(CI)M" | Out-Null
    if($LASTEXITCODE -ne 0){throw 'ERR_SERVICE_ACL'}
  }
}
$serviceKey="HKLM:\SYSTEM\CurrentControlSet\Services\$name"
if($PSCmdlet.ShouldProcess($serviceKey,'Set bounded service environment')){
  New-ItemProperty -Path $serviceKey -Name Environment -PropertyType MultiString -Value $serviceEnvironment -Force | Out-Null
}
if($Activate -and $PSCmdlet.ShouldProcess($name,'Activate and health-check service')){
  try {
    & sc.exe config $name start= demand | Out-Null; if($LASTEXITCODE -ne 0){throw 'ERR_SERVICE_CONFIG'}
    Start-Service -Name $name
    (Get-Service -Name $name).WaitForStatus('Running',[TimeSpan]::FromSeconds(15))
    if((Get-Service -Name $name).Status -ne 'Running'){throw 'ERR_INSTALL_HEALTH'}
  } catch {
    Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
    if($oldBinary){& sc.exe config $name binPath= $oldBinary start= demand | Out-Null; Start-Service -Name $name -ErrorAction SilentlyContinue}
    throw 'ERR_UPGRADE_ROLLBACK'
  }
}
# Without -Activate the service remains disabled and stopped. No firewall rule is altered.
