#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory=$true)][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$')][string]$Version,
  [switch]$Activate
)
$ErrorActionPreference='Stop'
$packageRoot=Split-Path -Parent $PSScriptRoot
$manifest=Join-Path $PSScriptRoot 'install-manifest.json'
$runtime=Join-Path $PSScriptRoot 'cli.js'
$serviceScript=Join-Path $PSScriptRoot 'Install-LANModelService.ps1'
foreach($path in @($manifest,$runtime,$serviceScript,(Join-Path $packageRoot 'bin\lan-model-agent.exe'))){if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw 'ERR_INSTALL_PACKAGE'}}
$node=(Get-Command node.exe -ErrorAction SilentlyContinue).Source
if(-not $node){throw 'ERR_INSTALL_NODE'}
$pointer=Join-Path $env:ProgramFiles 'LANModelManager\agent.current'
$action=if(Test-Path -LiteralPath $pointer -PathType Leaf){'upgrade'}else{'install'}
$serviceAction=if($action -eq 'upgrade'){'Upgrade'}else{'Install'}
$args=@($runtime,$action,'--platform','windows','--payload',$packageRoot,'--manifest',$manifest,'--role','agent')
$serviceArgs=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$serviceScript,'-Role','agent','-Version',$Version,'-Action',$serviceAction)
if($Activate){$serviceArgs+='-Activate'}
if($WhatIfPreference){
  $args+='--dry-run';$serviceArgs+='-WhatIf'
  & $node @args
  if($LASTEXITCODE -ne 0){throw 'ERR_INSTALL_STAGE'}
  & powershell.exe @serviceArgs
  if($LASTEXITCODE -ne 0){throw 'ERR_INSTALL_SERVICE'}
  return
}
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ERR_INSTALL_ADMIN'}
if($PSCmdlet.ShouldProcess('LAN Model Manager Agent',"$serviceAction verified package $Version")){
  & $node @args
  if($LASTEXITCODE -ne 0){throw 'ERR_INSTALL_STAGE'}
  & powershell.exe @serviceArgs
  if($LASTEXITCODE -ne 0){throw 'ERR_INSTALL_SERVICE'}
}
