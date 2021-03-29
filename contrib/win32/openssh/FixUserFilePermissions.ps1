[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
param ()
Set-StrictMode -Version 2.0
If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}

Import-Module $PSScriptRoot\OpenSSHUtils -Force

if(Test-Path ~\.ssh\config -PathType Leaf)
{
    Repair-UserSshConfigPermission -FilePath ~\.ssh\config @psBoundParameters
}

Get-ChildItem ~\.ssh\* -Include "id_rsa","id_dsa" -ErrorAction SilentlyContinue | % {
    Repair-UserKeyPermission -FilePath $_.FullName @psBoundParameters
}


if (([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")))
{
    $sshdAdministratorsAuthorizedKeysPath = join-path $env:ProgramData\ssh "administrators_authorized_keys"
    if(Test-Path $sshdAdministratorsAuthorizedKeysPath -PathType Leaf) 
    {
        Repair-AdministratorsAuthorizedKeysPermission -FilePath $sshdAdministratorsAuthorizedKeysPath @psBoundParameters
    }
    else 
    {
        Write-host "$sshdAdministratorsAuthorizedKeysPath does not exist"  -ForegroundColor Yellow
    }
}

Write-Host "   Done."
Write-Host " "
