#Requires -Version 5.1
# Safe native fixture: extract only the production configuration functions, then
# substitute BOTH CIM commands. Never execute the installer or mutate services.
$ErrorActionPreference='Stop'
$installer=Join-Path $PSScriptRoot '..\templates\windows\Install-LANModelService.ps1'
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($installer,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count-ne 0){throw 'installer parse failed'}
foreach($name in @('Assert-ServiceConfiguration','Set-ServiceConfiguration')){
  $function=$ast.Find({param($node) $node-is[Management.Automation.Language.FunctionDefinitionAst]-and$node.Name-eq$name},$true)
  if($null-eq$function){throw 'production function missing'}
  . ([ScriptBlock]::Create($function.Extent.Text))
}
$script:path='"C:\Program Files\LANModelManager\releases\agent\0.1.0-alpha.6\bin\lan-model-agent.exe"'
$script:account='NT SERVICE\LANModelAgent';$script:mode='Disabled';$script:failure='';$script:calls=0
function Get-CimInstance {
  param($ClassName,$Filter,$ErrorAction)
  if($ClassName-ne'Win32_Service'-or$Filter-ne"Name='LANModelAgent'"){throw 'unexpected query'}
  if($script:failure-eq'missing'){return $null}
  $readPath=$script:path;$readAccount=$script:account;$readMode=$script:mode
  if($script:calls-gt 0){
    if($script:failure-eq'quotes-lost'){$readPath=$readPath.Trim('"')}
    if($script:failure-eq'wrong-account'){$readAccount='LocalSystem'}
    if($script:failure-eq'wrong-mode'){$readMode='Auto'}
  }
  return [pscustomobject]@{PathName=$readPath;StartName=$readAccount;StartMode=$readMode}
}
function Invoke-CimMethod {
  param($InputObject,$MethodName,[hashtable]$Arguments,$ErrorAction)
  if($MethodName-ne'Change'-or$Arguments.Count-ne 3-or$Arguments.PathName-cne$script:expectedPath-or$Arguments.StartName-cne$script:account){throw 'typed arguments changed'}
  $script:calls++
  if($script:failure-eq'null-result'){return $null}
  if($script:failure-eq'no-return-value'){return [pscustomobject]@{Other=0}}
  if($script:failure-eq'change-denied'){return [pscustomobject]@{ReturnValue=2}}
  $script:path=$Arguments.PathName
  $script:mode=if($Arguments.StartMode-eq'Automatic'){'Auto'}else{$Arguments.StartMode}
  return [pscustomobject]@{ReturnValue=0}
}
# Create/upgrade and rollback preserve literal quotes through the production
# typed boundary. Automatic's setter/readback spelling is deliberately distinct.
foreach($version in @('0.1.0-alpha.7','0.1.0-alpha.6')){
  $script:expectedPath='"C:\Program Files\LANModelManager\releases\agent\'+$version+'\bin\lan-model-agent.exe"'
  Set-ServiceConfiguration 'LANModelAgent' $script:expectedPath 'Disabled' $script:account
  if($script:path-cne$script:expectedPath){throw 'literal quotes lost'}
}
Set-ServiceConfiguration 'LANModelAgent' $script:expectedPath 'Automatic' $script:account
Set-ServiceConfiguration 'LANModelAgent' $script:expectedPath 'Manual' $script:account
foreach($failure in @('quotes-lost','wrong-account','wrong-mode','null-result','no-return-value','change-denied','missing')){
  $script:failure=$failure;$script:calls=0;$caught=$false
  try{Set-ServiceConfiguration 'LANModelAgent' $script:expectedPath 'Disabled' $script:account}catch{
    if($_.Exception.Message-notmatch'^ERR_SERVICE_CONFIG(?:_READBACK)?$'){throw}
    $caught=$true
  }
  if(-not$caught){throw "failure did not fail closed: $failure"}
}
Write-Output 'PASS typed service configuration, rollback, and fail-closed readback (mock CIM; no live service changes)'
