##
## Azure DevOps CI build tools
## [Add appropriate copyright]
##

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Get-RepositoryRoot
$script:messageFile = join-path $repoRoot.FullName "BuildMessage.log"

function Write-BuildMessage
{
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Message,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Category
    )

    # Write message to verbose stream.
    Write-Verbose -Verbose -Message "$Category--$Message"

    # Write it to the log file, if present.
    if (-not ([string]::IsNullOrEmpty($script:messageFile)))
    {
        Add-Content -Path $script:messageFile -Value "$Category--$Message"
    }
}

<#
    .Synopsis
    Adds a build log to the list of published artifacts.
    .Description
    If a build log exists, it is renamed to reflect the associated CLR runtime then added to the list of
    artifacts to publish.  If it doesn't exist, a warning is written and the file is skipped.
    The rename is needed since publishing overwrites the artifact if it already exists.
    .Parameter artifacts
    An array list to add the fully qualified build log path
    .Parameter buildLog
    The build log file produced by the build.    
#>
function Add-BuildLog
{
    param (
        [ValidateNotNull()]
        [System.Collections.ArrayList] $artifacts,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $buildLog
    )

    if (Test-Path -Path $buildLog)
    {   
        $null = $artifacts.Add($buildLog)
    }
    else
    {
        Write-Warning "Skip publishing build log. $buildLog does not exist"
    }
}

function Set-BuildVariable
{
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $Value
    )

    Set-Item -Path env:$Name -Value $Value
}

# Emulates running all of AzDO functions locally.
# This should not be used within an actual AzDO build.
function Invoke-AllLocally
{
    param (
        [switch] $CleanRepo
    )

    if ($CleanRepo)
    {
        Clear-PSRepo
    }

    # TODO: Set up any build environment state here.

    try
    {        
        Invoke-AzDOBuild
        Install-OpenSSH
        Set-OpenSSHTestEnvironment -confirm:$false
        Invoke-OpenSSHTests
        Publish-Artifact
    }
    finally
    {
        # TODO: Clean up any build environment state here.
    }
}

# Implements the AzDO build package step
function Invoke-AzDOBuild
{
      Set-BuildVariable TestPassed True
      Start-OpenSSHBuild -Configuration Release -NativeHostArch x64 -Verbose
      Start-OpenSSHBuild -Configuration Release -NativeHostArch x86 -Verbose
      Write-BuildMessage -Message "OpenSSH binaries build success!" -Category Information
}

<#
    .Synopsis
    Deploy all required files to a location and install the binaries
#>
function Install-OpenSSH
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$true)]
        [string]$SourceDir,

        [string]$OpenSSHDir = "$env:SystemDrive\OpenSSH"
    )

    UnInstall-OpenSSH -OpenSSHDir $OpenSSHDir

    if (! (Test-Path -Path $OpenSSHDir)) {
        $null = New-Item -Path $OpenSSHDir -ItemType Directory -Force
    }

    Copy-Item -Path "$SourceDir/*" -Destination $OpenSSHDir -Recurse -Force -Verbose

    Push-Location $OpenSSHDir 

    try
    {
        & "$OpenSSHDir\install-sshd.ps1"

        $machinePath = [Environment]::GetEnvironmentVariable('Path', 'MACHINE')
        $newMachineEnvironmentPath = $machinePath
        if (-not ($machinePath.ToLower().Contains($OpenSSHDir.ToLower())))
        {
            $newMachineEnvironmentPath = "$OpenSSHDir;$newMachineEnvironmentPath"
            $env:Path = "$OpenSSHDir;$env:Path"
        }

        # Update machine environment path
        if ($newMachineEnvironmentPath -ne $machinePath)
        {
            [Environment]::SetEnvironmentVariable('Path', $newMachineEnvironmentPath, 'MACHINE')
        }
        
        Start-Service -Name sshd 
        Start-Service -Name ssh-agent
    }
    finally
    {
        Pop-Location
    }

    Write-BuildMessage -Message "OpenSSH installed!" -Category Information
}

<#
    .Synopsis
    uninstalled sshd
#>
function UnInstall-OpenSSH
{
    [CmdletBinding()]
    param ( 
        [string]$OpenSSHDir = "$env:SystemDrive\OpenSSH"
    )

    if (-not (Test-Path $OpenSSHDir -PathType Container))
    {
        return
    }

    Push-Location $OpenSSHDir

    try
    {
        if ((Get-Service ssh-agent -ErrorAction SilentlyContinue) -ne $null) {
            Stop-Service ssh-agent -Force
        }
        & "$OpenSSHDir\uninstall-sshd.ps1"
            
        $machinePath = [Environment]::GetEnvironmentVariable('Path', 'MACHINE')
        $newMachineEnvironmentPath = $machinePath
        if ($machinePath.ToLower().Contains($OpenSSHDir.ToLower()))
        {        
            $newMachineEnvironmentPath = $newMachineEnvironmentPath.Replace("$OpenSSHDir;", '')
            $env:Path = $env:Path.Replace("$OpenSSHDir;", '')
        }
        
        if ($newMachineEnvironmentPath -ne $machinePath)
        {
            [Environment]::SetEnvironmentVariable('Path', $newMachineEnvironmentPath, 'MACHINE')
        }
    }
    finally
    {
        Pop-Location
    }

    Remove-Item -Path $OpenSSHDir -Recurse -Force -ErrorAction SilentlyContinue    
}

<#
    .Synopsis
    Publishes package build artifacts.    
    .Parameter artifacts
    An array list to add the fully qualified build log path
    .Parameter FileToAdd
    Path to the file
#>
function Add-Artifact
{
    param (
        [ValidateNotNull()]
        [System.Collections.ArrayList] $artifacts,
        [string] $FileToAdd
    )        
    
    if ([string]::IsNullOrEmpty($FileToAdd) -or (-not (Test-Path $FileToAdd -PathType Leaf)) )
    {            
        Write-Host "Skip publishing package artifacts. $FileToAdd does not exist"
    }    
    else
    {
        $null = $artifacts.Add($FileToAdd)
        Write-Host "Added $FileToAdd to publishing package artifacts"
    }
}

<#
    .Synopsis
    After build and test run completes, upload all artifacts from the build machine.
#>
function Publish-Artifact
{
    Write-Host -ForegroundColor Yellow "Publishing project artifacts"
    [System.Collections.ArrayList] $artifacts = new-object System.Collections.ArrayList
    
    # Get the build.log file for each build configuration        
    Add-BuildLog -artifacts $artifacts -buildLog (Get-BuildLogFile -root $repoRoot.FullName -Configuration Release -NativeHostArch x64)
    Add-BuildLog -artifacts $artifacts -buildLog (Get-BuildLogFile -root $repoRoot.FullName -Configuration Release -NativeHostArch x86)

    if($Global:OpenSSHTestInfo)
    {
        Add-Artifact -artifacts $artifacts -FileToAdd $Global:OpenSSHTestInfo["SetupTestResultsFile"]
        Add-Artifact -artifacts $artifacts -FileToAdd $Global:OpenSSHTestInfo["UnitTestResultsFile"]
        Add-Artifact -artifacts $artifacts -FileToAdd $Global:OpenSSHTestInfo["E2ETestResultsFile"]
        Add-Artifact -artifacts $artifacts -FileToAdd $Global:OpenSSHTestInfo["UninstallTestResultsFile"]
        Add-Artifact -artifacts $artifacts -FileToAdd $Global:OpenSSHTestInfo["TestSetupLogFile"]
    }

    if ($Global:bash_tests_summary)
    {
        Add-Artifact -artifacts $artifacts -FileToAdd $Global:bash_tests_summary["BashTestSummaryFile"]
        Add-Artifact -artifacts $artifacts -FileToAdd $Global:bash_tests_summary["BashTestLogFile"]
    }
    
    foreach ($artifact in $artifacts)
    {
        Write-Host "Publishing $artifact as AzDO artifact"

        # TODO: Create an AzDO artificate upload function.
        # Push-AppveyorArtifact $artifact -ErrorAction Continue
    }

    Write-Host -ForegroundColor Yellow "End of publishing project artifacts"
}

#
# Install CygWin from Chocolatey and fix up install directory if needed.
#
function Install-CygWin
{
    param (
        [string] $InstallLocation
    )

    Write-Verbose -Verbose -Message "Installing CygWin from Chocolately to location: ${InstallLocation} ..."
    choco install cygwin -y --params "/InstallDir:${InstallLocation} /NoStartMenu"
}

<#
      .Synopsis
      Runs the tests for this repo
#>
function Invoke-OpenSSHTests
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string] $OpenSSHBinPath
    )

    Set-BasicTestInfo -OpenSSHBinPath $OpenSSHBinPath -Confirm:$false

    Write-Verbose -Verbose -Message "Running OpenSSH Set up Tests..."
    Set-BuildVariable -Name 'TestPassed' -Value 'True'

    Invoke-OpenSSHSetupTest
    if (($OpenSSHTestInfo -eq $null) -or (-not (Test-Path $OpenSSHTestInfo["SetupTestResultsFile"])))
    {
        Write-Warning "Test result file $OpenSSHTestInfo["SetupTestResultsFile"] not found after tests."
        Write-BuildMessage -Message "Test result file $OpenSSHTestInfo["SetupTestResultsFile"] not found after tests." -Category Error
        Set-BuildVariable -Name 'TestPassed' -Value 'False'
        Write-Warning "Stop running further tests!"
        return
    }
    $xml = [xml](Get-Content $OpenSSHTestInfo["SetupTestResultsFile"] | out-string)
    if ([int]$xml.'test-results'.failures -gt 0) 
    {
        $errorMessage = "$($xml.'test-results'.failures) setup tests in regress\pesterTests failed. Detail test log is at $($OpenSSHTestInfo["SetupTestResultsFile"])."
        Write-Warning $errorMessage
        Write-BuildMessage -Message $errorMessage -Category Error
        Set-BuildVariable -Name 'TestPassed' -Value 'False'
        Write-Warning "Stop running further tests!"
        return
    }

    Write-Host "Start running unit tests"

    # Unit test directories are installed in the same directory as Open SSH binaries.
    #  OpenSSH Directory
    #    unittest-bitmap
    #    unittest-hostkeys
    #    ...
    #    FixHostFilePermissions.ps1
    #    ...
    Write-Verbose -Verbose -Message "Running Unit Tests..."
    Write-Verbose -Verbose -Message "Unit test directory is: ${OpenSSHBinPath}"

    $unitTestFailed = Invoke-OpenSSHUnitTest -UnitTestDirectory $OpenSSHBinPath

    if($unitTestFailed)
    {
        Write-Host "At least one of the unit tests failed!" -ForegroundColor Yellow
        Write-BuildMessage "At least one of the unit tests failed!" -Category Error
        Set-BuildVariable -Name 'TestPassed' -Value 'False'
    }
    else
    {
        Write-Host "All Unit tests passed!"
        Write-BuildMessage -Message "All Unit tests passed!" -Category Information
    }

    # Run all E2E tests.
    Write-Verbose -Verbose -Message "Running E2E Tests..."
    Set-OpenSSHTestEnvironment -Confirm:$false
    Invoke-OpenSSHE2ETest
    if (($OpenSSHTestInfo -eq $null) -or (-not (Test-Path $OpenSSHTestInfo["E2ETestResultsFile"])))
    {
        Write-Warning "Test result file $OpenSSHTestInfo["E2ETestResultsFile"] not found after tests."
        Write-BuildMessage -Message "Test result file $OpenSSHTestInfo["E2ETestResultsFile"] not found after tests." -Category Error
        Set-BuildVariable -Name 'TestPassed' -Value 'False'
        Write-Warning "Stop running further tests!"
        return
    }
    $xml = [xml](Get-Content $OpenSSHTestInfo["E2ETestResultsFile"] | out-string)
    if ([int]$xml.'test-results'.failures -gt 0)
    {
        $errorMessage = "$($xml.'test-results'.failures) tests in regress\pesterTests failed. Detail test log is at $($OpenSSHTestInfo["E2ETestResultsFile"])."
        Write-Warning $errorMessage
        Write-BuildMessage -Message $errorMessage -Category Error
        Set-BuildVariable -Name 'TestPassed' -Value 'False'
        Write-Warning "Stop running further tests!"
        return
    }

    # Bash tests.
    Write-Verbose -Verbose -Message "Running Bash Tests..."

    # Ensure CygWin is installed, and install from Chocolatey if needed.
    $cygwinInstallLocation = "$env:SystemDrive/cygwin"
    if (! (Test-Path -Path "$cygwinInstallLocation/bin/sh.exe"))
    {
        Write-Verbose -Verbose -Message "CygWin not found"
        Install-CygWin -InstallLocation $cygwinInstallLocation

        # Hack to fix up mangled CygWin directory, if needed.
        $cygWinDirs = Get-Item -Path "$env:SystemDrive/cygwin"
        if ($cygWinDirs.Count -gt 1)
        {
            Write-Verbose -Verbose -Message "CygWin install failed with mangled folder locations: ${cygWinDirs}"
            # TODO: Add hack to fix up CygWin folder.
        }
    }

    # Run UNIX bash tests.
    Invoke-OpenSSHBashTests
    if (-not $Global:bash_tests_summary)
    {
        $errorMessage = "Failed to start OpenSSH bash tests"
        Write-Warning $errorMessage
        Write-BuildMessage -Message $errorMessage -Category Error
        Set-BuildVariable -Name 'TestPassed' -Value 'False'
        Write-Warning "Stop running further tests!"
        return
    }

    if ($Global:bash_tests_summary["TotalBashTestsFailed"] -ne 0)
    {
        $total_bash_failed_tests = $Global:bash_tests_summary["TotalBashTestsFailed"]
        $total_bash_tests = $Global:bash_tests_summary["TotalBashTests"]
        $errorMessage = "At least one of the bash tests failed. [$total_bash_failed_tests of $total_bash_tests]"
        Write-Warning $errorMessage
        Write-BuildMessage -Message $errorMessage -Category Error
        Set-BuildVariable -Name 'TestPassed' -Value 'False'
        Write-Warning "Stop running further tests!"
        return
    }

    # OpenSSH Uninstall Tests
    Invoke-OpenSSHUninstallTest
    if (($OpenSSHTestInfo -eq $null) -or (-not (Test-Path $OpenSSHTestInfo["UninstallTestResultsFile"])))
    {
        Write-Warning "Test result file $OpenSSHTestInfo["UninstallTestResultsFile"] not found after tests."
        Write-BuildMessage -Message "Test result file $OpenSSHTestInfo["UninstallTestResultsFile"] not found after tests." -Category Error
        Set-BuildVariable -Name 'TestPassed' -Value 'False'
    }
    else {
        $xml = [xml](Get-Content $OpenSSHTestInfo["UninstallTestResultsFile"] | out-string)
        if ([int]$xml.'test-results'.failures -gt 0) 
        {
            $errorMessage = "$($xml.'test-results'.failures) uninstall tests in regress\pesterTests failed. Detail test log is at $($OpenSSHTestInfo["UninstallTestResultsFile"])."
            Write-Warning $errorMessage
            Write-BuildMessage -Message $errorMessage -Category Error
            Set-BuildVariable -Name 'TestPassed' -Value 'False'
        }
    }

    # Writing out warning when the $Error.Count is non-zero. Tests Should clean $Error after success.
    if ($Error.Count -gt 0) 
    {
        Write-BuildMessage -Message "Tests Should clean $Error after success." -Category Warning
    }
}

<#
      .Synopsis
      Collect OpenSSH pester test results into one directory
#>
function Copy-OpenSSHTestResults
{ 
    param (
        [Parameter(Mandatory=$true)]
        [string] $ResultsPath
    )

    if (Test-Path -Path $ResultsPath)
    {
        Remove-Item -Path $ResultsPath -Force -Recurse -ErrorAction Ignore
    }

    Write-Verbose -Verbose "Creating test results directory for artifacts upload: $ResultsPath"
    $null = New-Item -Path $ResultsPath -ItemType Directory -Force
    
    if (Test-Path -Path $ResultsPath)
    {
        $setupresultFile = Resolve-Path $Global:OpenSSHTestInfo["SetupTestResultsFile"] -ErrorAction Ignore
        if ($setupresultFile)
        {
            Write-Verbose -Verbose "Copying set-up test results file, $setupresultFile, to results directory"
            Copy-Item -Path $setupresultFile -Destination $ResultsPath
        }

        $E2EresultFile = Resolve-Path $Global:OpenSSHTestInfo["E2ETestResultsFile"] -ErrorAction Ignore
        if ($E2EresultFile)
        {
            Write-Verbose -Verbose "Copying end-to-end test results file, $E2EresultFile, to results directory"
            Copy-Item -Path $E2EresultFile -Destination $ResultsPath
        }

        $uninstallResultFile = Resolve-Path $Global:OpenSSHTestInfo["UninstallTestResultsFile"] -ErrorAction Ignore
        if ($uninstallResultFile)
        {
            Write-Verbose -Verbose "Copying uninstall test results file, $uninstallResultFile, to results directory"
            Copy-Item -Path $uninstallResultFile -Destination $ResultsPath
        }
    }
    else
    {
        Write-Verbose -Verbose "Unable to write test results path for test artifacts upload: $ResultsPath"
    }

    if ($env:DebugMode)
    {
        Remove-Item $env:DebugMode
    }
    
    if ($env:TestPassed -eq 'True')
    {
        Write-BuildMessage -Message "The checkin validation tests succeeded!" -Category Information
    }
    else
    {
        Write-BuildMessage -Message "The checkin validation tests failed!" -Category Error
        throw "The checkin validation tests failed!"
    }
}

<#
    .SYNOPSIS
    Copy build results package to provided destination path.
#>
function Copy-BuildResults
{
    param (
        [Parameter(Mandatory=$true)]
        [string] $BuildResultsPath,

        [ValidateSet('x86', 'x64', 'arm64', 'arm')]
        [string]$NativeHostArch = "x64",

        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = "Release"
    )

    # Copy OpenSSH package to results directory
    Start-OpenSSHPackage -DestinationPath $BuildResultsPath -NativeHostArch $NativeHostArch -Configuration $Configuration
}

<#
    .SYNOPSIS
    Copy build unit tests to provided destination path.
#>
function Copy-UnitTests
{
    param (
        [Parameter(Mandatory=$true)]
        [string] $UnitTestsSrcDir,

        [Parameter(Mandatory=$true)]
        [string] $UnitTestsDestDir,

        [ValidateSet('x86', 'x64', 'arm64', 'arm')]
        [string]$NativeHostArch = "x64",

        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = "Release"
    )

    if (! (Test-Path -Path $UnitTestsDestDir))
    {
      Write-Verbose -Verbose -Message "Creating Unit Test directory: $UnitTestsDestDir"
      $null = New-Item -Path $UnitTestsDestDir -ItemType Directory -Force
    }

    if ($NativeHostArch -eq 'x86')
    {
        $unitTestsSrcPath = Join-Path -Path $UnitTestsSrcDir -ChildPath "Win32/${Configuration}"
    }
    else
    {
        $unitTestsSrcPath = Join-Path -Path $UnitTestsSrcDir -ChildPath "${NativeHostArch}/${Configuration}"
    }

    $unitTestsDestPath = Join-Path -Path $UnitTestsDestDir -ChildPath "${NativeHostArch}/${Configuration}"

    if (! (Test-Path -Path $unitTestsDestPath))
    {
      Write-Verbose -Verbose -Message "Creating Unit Test directory: $unitTestsDestPath"
      $null = New-Item -Path $unitTestsDestPath -ItemType Directory -Force
    }

    Write-Verbose -Verbose -Message "Copying unit tests from: ${unitTestsSrcPath} to: ${unitTestsDestPath}"
    Copy-Item -Path "$unitTestsSrcPath/unittest-*" -Destination $unitTestsDestPath -Recurse -Force
}

<#
    .SYNOPSIS
    Install unit tests to provided destination.
#>
function Install-UnitTests
{
    [CmdletBinding()]
    param ( 
        [Parameter(Mandatory=$true)]
        [string]$SourceDir,

        [string]$OpenSSHDir = "$env:SystemDrive\OpenSSH"
    )

    if (! (Test-Path -Path $OpenSSHDir)) {
        $null = New-Item -Path $OpenSSHDir -ItemType Directory -Force
    }

    Copy-Item -Path "$SourceDir/*" -Destination $OpenSSHDir -Recurse -Force
}
