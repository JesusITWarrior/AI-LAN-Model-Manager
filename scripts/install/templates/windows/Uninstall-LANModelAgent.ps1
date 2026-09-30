#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([switch]$Purge)
$ErrorActionPreference='Stop'
$packageRoot=Split-Path -Parent $PSScriptRoot
$runtime=Join-Path $PSScriptRoot 'cli.js'
$serviceScript=Join-Path $PSScriptRoot 'Install-LANModelService.ps1'
foreach($path in @($runtime,$serviceScript)){if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw 'ERR_UNINSTALL_PACKAGE'}}
$node=(Get-Command node.exe -ErrorAction SilentlyContinue).Source
if(-not $node){throw 'ERR_INSTALL_NODE'}
$summary=if($Purge){'remove the service, application files, enrollment state, and configuration'}else{'remove the service and application files while preserving enrollment state and configuration'}
$serviceArgs=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$serviceScript,'-Role','agent','-Action','Uninstall')
$args=@($runtime,'uninstall','--platform','windows','--role','agent')
if($Purge){$serviceArgs+='-Purge';$args+='--purge'}
if($WhatIfPreference){
  $serviceArgs+='-WhatIf';$args+='--dry-run'
  & powershell.exe @serviceArgs
  if($LASTEXITCODE -ne 0){throw 'ERR_UNINSTALL_SERVICE'}
  & $node @args
  if($LASTEXITCODE -ne 0){throw 'ERR_UNINSTALL_FILES'}
  return
}
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ERR_INSTALL_ADMIN'}
if($PSCmdlet.ShouldProcess('LAN Model Manager Agent',$summary)){
  & powershell.exe @serviceArgs
  if($LASTEXITCODE -ne 0){throw 'ERR_UNINSTALL_SERVICE'}
  & $node @args
  if($LASTEXITCODE -ne 0){throw 'ERR_UNINSTALL_FILES'}
}
