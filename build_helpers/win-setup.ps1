<#
.SYNOPSIS
    Builds the SMB fixture layout that the jcifs integration tests expect.

.DESCRIPTION
    Creates the same share vocabulary as build_helpers/samba/entrypoint.sh, so the
    same tests run against either backend. Intended for a GitHub Actions
    windows-latest runner (Windows Server 2025, administrator, UAC disabled) and
    for a local Windows VM.

    DFS Namespaces is a server role. On a client SKU such as Windows 11 the DFS
    section is skipped and the DFS tests skip with it.

.PARAMETER Password
    Password for the test accounts. This is a throwaway credential that is only
    valid on the machine running this script.
#>
[CmdletBinding()]
param(
    [String] $Password = 'Public-Fixture-Not-A-Secret-1!',
    [String] $Root = 'C:\smbit',
    [String] $OutsideRoot = 'C:\smbit-outside'
)

$ErrorActionPreference = 'Stop'

$testUsers = @('testuser1', 'testuser2')
$securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force

Write-Host 'Creating local test accounts'
foreach ($user in $testUsers) {
    if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $user -Password $securePassword -PasswordNeverExpires -AccountNeverExpires `
            -UserMayNotChangePassword -Description 'jcifs integration test account' | Out-Null
    }
}

Write-Host 'Creating share directories'
$shareNames = @('share', 'share-encrypted', 'dfs', 'public', 'users', 'testuser1private', 'testuser2private')
foreach ($name in $shareNames) {
    New-Item -Path (Join-Path $Root $name) -ItemType Directory -Force | Out-Null
}
New-Item -Path $OutsideRoot -ItemType Directory -Force | Out-Null

# Both accounts share the common directories.
foreach ($name in @('share', 'share-encrypted', 'dfs', 'public', 'users')) {
    icacls (Join-Path $Root $name) /grant 'testuser1:(OI)(CI)F' 'testuser2:(OI)(CI)F' /T /Q | Out-Null
}
icacls $OutsideRoot /grant 'testuser1:(OI)(CI)F' 'testuser2:(OI)(CI)F' /T /Q | Out-Null

# The private directories are private at the NTFS layer as well as the share
# layer, the way a real deployment would restrict them. Inheritance is turned off
# first: a grant applied with /T leaves an explicit ACE that /inheritance:r would
# not remove.
foreach ($user in $testUsers) {
    $privatePath = Join-Path $Root "${user}private"
    icacls $privatePath /inheritance:r /Q | Out-Null
    icacls $privatePath /grant 'BUILTIN\Administrators:(OI)(CI)F' 'NT AUTHORITY\SYSTEM:(OI)(CI)F' "${user}:(OI)(CI)F" /T /Q | Out-Null
}

Write-Host 'Creating SMB shares'
$sharedByBoth = @('share', 'dfs', 'public', 'users')
foreach ($name in $sharedByBoth) {
    if (-not (Get-SmbShare -Name $name -ErrorAction SilentlyContinue)) {
        New-SmbShare -Name $name -Path (Join-Path $Root $name) -FullAccess $testUsers -EncryptData $false | Out-Null
    }
}
if (-not (Get-SmbShare -Name 'share-encrypted' -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name 'share-encrypted' -Path (Join-Path $Root 'share-encrypted') -FullAccess $testUsers `
        -EncryptData $true | Out-Null
}
foreach ($user in $testUsers) {
    $privateShare = "${user}private"
    if (-not (Get-SmbShare -Name $privateShare -ErrorAction SilentlyContinue)) {
        New-SmbShare -Name $privateShare -Path (Join-Path $Root $privateShare) -FullAccess $user -EncryptData $false | Out-Null
    }
}

Write-Host 'Requiring SMB signing'
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

Write-Host 'Creating symlink fixtures'
$sharePath = Join-Path $Root 'share'
[IO.File]::WriteAllText((Join-Path $sharePath 'target.txt'), "target file contents`n")
New-Item -Path (Join-Path $sharePath 'subdir') -ItemType Directory -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $sharePath 'subdir\inside.txt'), "inside subdir`n")
[IO.File]::WriteAllText((Join-Path $OutsideRoot 'outside.txt'), "outside the share`n")

$links = @(
    @{ Name = 'link-to-file'; Target = (Join-Path $sharePath 'target.txt') },
    @{ Name = 'link-to-dir'; Target = (Join-Path $sharePath 'subdir') },
    @{ Name = 'link-broken'; Target = (Join-Path $sharePath 'missing.txt') },
    @{ Name = 'link-outside'; Target = (Join-Path $OutsideRoot 'outside.txt') }
)
foreach ($link in $links) {
    $path = Join-Path $sharePath $link.Name
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType SymbolicLink -Path $path -Target $link.Target | Out-Null
    }
}
# A relative link, created from inside the directory so the target stays relative.
Push-Location $sharePath
try {
    if (-not (Test-Path -LiteralPath 'link-relative')) {
        cmd.exe /c 'mklink link-relative target.txt' | Out-Null
    }
} finally {
    Pop-Location
}

if (Get-Command -Name Install-WindowsFeature -ErrorAction SilentlyContinue) {
    Write-Host 'Installing the DFS Namespaces role'
    Install-WindowsFeature -Name FS-DFS-Namespace -IncludeManagementTools | Out-Null

    $dfsPath = "\\$env:COMPUTERNAME\dfs"
    if (-not (Get-DfsnRoot -Path $dfsPath -ErrorAction SilentlyContinue)) {
        New-DfsnRoot -Path $dfsPath -TargetPath $dfsPath -Type Standalone -State Online -TargetState Online | Out-Null
    }

    Write-Host 'Creating DFS links'
    # "link" and "link-extra" share a prefix on purpose: unbounded prefix matching
    # in the referral code was the defect behind both #86 and #88.
    $dfsFolders = @(
        @{ Name = 'link'; Target = "\\$env:COMPUTERNAME\share" },
        @{ Name = 'link-extra'; Target = "\\$env:COMPUTERNAME\users" },
        @{ Name = 'multi'; Target = "\\$env:COMPUTERNAME\missing" },
        @{ Name = 'broken'; Target = "\\$env:COMPUTERNAME\missing" }
    )
    foreach ($folder in $dfsFolders) {
        $folderPath = "$dfsPath\$($folder.Name)"
        if (-not (Get-DfsnFolder -Path $folderPath -ErrorAction SilentlyContinue)) {
            New-DfsnFolder -Path $folderPath -TargetPath $folder.Target -State Online -TargetState Online | Out-Null
        }
    }
    # A second, reachable target so "multi" exercises failover past the dead one.
    $multiPath = "$dfsPath\multi"
    $liveTarget = "\\$env:COMPUTERNAME\share"
    if (-not (Get-DfsnFolderTarget -Path $multiPath -TargetPath $liveTarget -ErrorAction SilentlyContinue)) {
        New-DfsnFolderTarget -Path $multiPath -TargetPath $liveTarget -State Online | Out-Null
    }
} else {
    Write-Warning 'Install-WindowsFeature is unavailable (client SKU); skipping DFS. The DFS tests will skip.'
}

Write-Host 'Enabling the SMB firewall rule and starting the server service'
Set-NetFirewallRule -Name FPS-SMB-In-TCP -Enabled True
Set-Service -Name LanmanServer -StartupType Automatic -Status Running

Write-Host ''
Write-Host 'NTFS permissions on the private shares:'
foreach ($user in $testUsers) {
    icacls (Join-Path $Root "${user}private") | Out-String | Write-Host
}

Write-Host 'Share permissions as configured:'
Get-SmbShare | Where-Object { $_.Name -ne 'IPC$' } | Get-SmbShareAccess |
    Format-Table -AutoSize ScaleOut, Name, AccountName, AccessControlType, AccessRight | Out-String | Write-Host

Write-Host ''
Write-Host "SMB fixtures are ready. Point the tests at JCIFS_IT_HOST=$env:COMPUTERNAME"
