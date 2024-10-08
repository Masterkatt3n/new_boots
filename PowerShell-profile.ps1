### PowerShell template profile 
### Version 1.03 - Tim Sneath <tim@sneath.org>
### From https://gist.github.com/timsneath/19867b12eee7fd5af2ba

# Initial GitHub.com connectivity check with 1 second timeout
$canConnectToGitHub = Test-Connection github.com -Count 1 -Quiet -TimeoutSeconds 1

# Drive shortcuts
function HKLM: { Set-Location HKLM: }
function HKCU: { Set-Location HKCU: }
function Env: { Set-Location Env: }

# Create new/empty profile file if not exists
if (!(Test-Path -Path $PROFILE)) { New-Item -ItemType File -Path $PROFILE -Force }

# Import Modules and External Profiles
# Ensure Terminal-Icons module is installed before importing
if (-not (Get-Module -ListAvailable -Name Terminal-Icons)) {
    Install-Module -Name Terminal-Icons -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module -Name Terminal-Icons
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

# Find out if the current user identity is elevated (has admin rights)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# and appends [ADMIN] if appropriate for easy taskbar identification
function prompt { 
    $location = if ($isAdmin) { "[{0}] # " -f (Get-Location) } else { "[{0}] $ " -f (Get-Location) }
    Write-Output $location
}
$Host.UI.RawUI.WindowTitle = "PowerShell {0}" -f $PSVersionTable.PSVersion.ToString()
if ($isAdmin) {
    $Host.UI.RawUI.WindowTitle += " [ADMIN]"
}
# We don't need these anymore; they were just temporary variables to get to $isAdmin. 
Remove-Variable identity
Remove-Variable principal

# Simple function to start a new elevated process. If arguments are supplied, then 
# a single command is started with admin rights; if not, then a new admin instance
# of PowerShell is started.
function admin {
    $argList = ""

    if ($args.Count -gt 0) {   
        $argList = "& '$args'"
        Start-Process -FilePath "$PSHome\pwsh.exe" -Verb runAs -ArgumentList $argList
    } else {
        Start-Process -FilePath 'pwsh.exe' -Verb runAs -ArgumentList $argList
    }
}

function Update-PowerShell {
    if (-not $global:canConnectToGitHub) {
        Write-Host "Skipping PowerShell update check due to GitHub.com not responding within 1 second." -ForegroundColor Yellow
        return
    }

    try {
        Write-Host "Checking for PowerShell updates..." -ForegroundColor Cyan
        $updateNeeded = $false
        $currentVersion = $PSVersionTable.PSVersion.ToString()
        $gitHubApiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
        $latestReleaseInfo = Invoke-RestMethod -Uri $gitHubApiUrl
        $latestVersion = $latestReleaseInfo.tag_name.Trim('v')
        if ($currentVersion -lt $latestVersion) {
            $updateNeeded = $true
        }

        if ($updateNeeded) {
            Write-Host "Updating PowerShell..." -ForegroundColor Yellow
            winget upgrade "Microsoft.PowerShell" --accept-source-agreements --accept-package-agreements
            Write-Host "PowerShell has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
        }
        else {
            Write-Host "Your PowerShell is up to date." -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to update PowerShell. Error: $_"
    }
}
Update-PowerShell

# Function to ensure Commands
function Test-CommandExists {
    param($command)
    return $null -ne (Get-Command $command -ErrorAction SilentlyContinue)
}

# Editor Configuration
if (Test-CommandExists 'notepad++') {
    $env:EDITOR = 'notepad++'
} elseif (Test-CommandExists 'vim') {
    $env:EDITOR = 'vim'
} elseif (Test-CommandExists 'vscodium') {
    $env:EDITOR = 'vscodium'
} else {
    $env:EDITOR = 'notepad'
}

# Function to open profile in Notepad++
function Edit-Profile {
    param(
        [string]$profilePath = $PROFILE
    )

    # If $profilePath is not defined or empty, use $PROFILE as the default
    if ([string]::IsNullOrEmpty($profilePath)) {
        $profilePath = $PROFILE
    }

    # Check if Notepad++ is installed and open the profile with it
    if (Test-CommandExists 'notepad++') {
        Start-Process "notepad++" $profilePath
    } else {
        Write-Host "Notepad++ is not installed. Opening profile with default editor."
        notepad $profilePath
    }
}
Set-Alias -Name ep -Value Edit-Profile # Create alias for editing profile

# Refresh the shell without exiting
function reload-profile {
    Write-Host "Reloading profile..."
    Write-Host "Current execution policy: $(Get-ExecutionPolicy)"
    Write-Host "Current profile location: $PROFILE"
    
    try {
        . $PROFILE
        Write-Host "Profile reloaded successfully."
    }
    catch {
        Write-Host "Error reloading profile: $_"
    }
}

function pgrep($name) {
    Get-Process $name
}

function head {
    param($Path, $n = 10)
    Get-Content $Path -Head $n
}

function tail {
    param($Path, $n = 10)
    Get-Content $Path -Tail $n
}
# Navigation Shortcuts
function docs { Set-Location -Path $HOME\Documents }
function dtop { Set-Location -Path $HOME\Desktop }
function .. { Set-Location .. }
function home {
    if (Get-Command zoxide -ErrorAction SilentlyContinue) {
        z ~
    } else {
        cd ~
    }
}

# System been online
function uptime {
    # Windows PowerShell only
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        Get-WmiObject win32_operatingsystem | Select-Object csname, @{LABEL='LastBootUpTime'; 
                EXPRESSION={ $_.ConverttoDateTime($_.lastbootuptime)}} 
    } else {
        net statistics workstation | Select-String "sedan" | foreach-object {$_.ToString().Replace('Statistik sedan', '')}
        New-TimeSpan (Get-uptime -Since) | Select-Object -Property Days, Hours, Minutes, Seconds
    }
}

# Search for a specific file
function Find-File($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "$($_.directory)/$($_)"
    }
}
Set-Alias -Name ff -Value Find-File

# Quick Access to System Information
function sysinfo { Get-ComputerInfo }

# Enhanced Listing
function la { Get-ChildItem -Path . -Force | Format-Table -AutoSize }
function ll { Get-ChildItem -Path . -Force -Hidden | Format-Table -AutoSize } 

# Networking Utilities
function flushdns { Clear-DnsClientCache }
function Get-PubIP { (Invoke-WebRequest http://ifconfig.me/ip ).Content }
Set-Alias -Name pubip -Value Get-PubIP

# Clipboard Utilities
function cpy { Set-Clipboard $args[0] }
function pst { Get-Clipboard }

# 
function unzip {
    param (
        [string]$source,
        [string]$destination
    )
    $shell = New-Object -ComObject shell.application
    $zip = $shell.NameSpace($source)
    $destinationFolder = $shell.NameSpace($destination)

    if ($null-eq $zip) {
        Write-Host "Invalid zip file path: $source"
        return
    }
    if ($null -eq $destinationFolder) {
        Write-Host "Invalid destination folder path: $destination"
        return
    }

    $destinationFolder.CopyHere($zip.Items(), 16)
    Write-Host "Unzipping complete."
}

# Aliases Linux Commands
function ix ($file) { curl.exe -F "f:1=@$file" ix.io }
function touch($file) { "" | Out-File $file -Encoding ASCII }
function df { get-volume }
function sed($file, $find, $replace) { (Get-Content $file).replace("$find", $replace) | Set-Content $file }
function which($name) { Get-Command $name | Select-Object -ExpandProperty Definition }
function export($name, $value) { set-item -force -path "env:$name" -value $value; }
function pkill($name) { Get-Process $name -ErrorAction SilentlyContinue | Stop-Process }
function pgrep($name) { Get-Process $name }

# The rough equivalent of dir /s /b. For example, dirs *.png is dir /s /b *.png
function dirs {
    $results = @()

    if ($args.Count -gt 0) {
        $results = Get-ChildItem -Recurse -Include $args | ForEach-Object { $_.FullName }
    } else {
        $results = Get-ChildItem -Recurse | ForEach-Object { $_.FullName }
    }

    $results | ForEach-Object {
        Write-Output $_
    }

    Write-Output "Counter: $($results.Count)"  # Output the amount of directories
}

function grep {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$regex,

        [Parameter(Position=1)]
        [string]$dir
    )

    try {
        if ($dir) {
            $files = Get-ChildItem $dir -File
            if ($files.Count -eq 0) {
                Write-Host "No files found in the specified directory."
                return
            }
            $files | ForEach-Object {
                try {
                    Get-Content $_.FullName -ErrorAction Stop | Select-String $regex
                }
                catch {
                    Write-Host "Error reading file $($_.FullName): $_"
                }
            }
        }
        else {
            Get-ChildItem | ForEach-Object {
                try {
                    Get-Content $_.FullName -ErrorAction Stop | Select-String $regex
                }
                catch {
                    Write-Host "Error reading file $($_.FullName): $_"
                }
            }
        }
    }
    catch {
        Write-Host "Error processing directory: $_"
    }
}
# Compute file hashes - useful for checking successful downloads 
function md5 { Get-FileHash -Algorithm MD5 $args }
function sha1 { Get-FileHash -Algorithm SHA1 $args }
function sha256 { Get-FileHash -Algorithm SHA256 $args }

# Initiate a graceful restart with a timeout of 10 seconds
function reboot { & shutdown.exe /r /t 10 /f /c "Restarting computer gracefully. Save your work." }

# Winget aliases
function wingetupdate { Winget list --upgrade-available }

# PSWindowsUpdate aliases
function gwu { Get-WindowsUpdate -Verbose }
function wuh { Get-WUHistory -Last 25 }
function wul { Get-WULastResults }
function iwu {
    param(
        [string]$Title,
        [string]$KBArticleID
    )
    
    # Create an array to hold the parameters
    $params = @{
        Install = $true
        Verbose = $true
        AcceptAll = $false
    }

    # Add parameters based on input
    if ($Title) { $params['Title'] = $Title }
    if ($KBArticleID) { $params['KBArticleID'] = $KBArticleID }
    
    # Call Get-WindowsUpdate with the parameters
    Get-WindowsUpdate @params
}

# Full packages upgrade function
function Update-All {
    Write-Host "Updating all packages using winget and Chocolatey..."

    try {
        # Update all packages using winget
        Write-Host "Updating packages with winget..."
        winget upgrade --all --accept-source-agreements --accept-package-agreements
        Write-Host "Winget packages updated successfully."
    }
    catch {
        Write-Host "Error updating Winget packages: $_"
        Pause  # Wait for user input to review the error
    }

    try {
        # Update all packages using Chocolatey
        Write-Host "Checking for outdated Chocolatey packages..."
        $outdated = choco outdated
        if ($outdated) {
            Write-Host "Updating Chocolatey packages..."
            choco upgrade all -y
            Write-Host "Chocolatey packages updated successfully."
        } else {
            Write-Host "No outdated Chocolatey packages found."
        }
    }
    catch {
        Write-Host "Error updating Chocolatey packages: $_"
        Pause  # Wait for user input to review the error
    }

    Write-Host "Package update process completed."
}

# Start HWiNFO
function hwinfo { Start-Process -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\HWiNFO64\HWiNFO® 64.lnk"; echo "running HWiNFO..." }

# Enhanced PowerShell Experience
Set-PSReadLineOption -Colors @{
    Command   = 'Yellow'
    Parameter = 'Green'
    String    = 'DarkCyan'
}

##################
#SAVING OLD STUFF
##################

# Check for Profile Updates
#function Update-Profile {
#    if (-not $global:canConnectToGitHub) {
#        Write-Host "Skipping profile update check due to GitHub.com not responding within 1 second." -ForegroundColor Yellow
#        return
#    }
#
#   try {
#        $url = "https://raw.githubusercontent.com/Masterkatt3n/new_boots/main/PowerShell-profile.ps1"
#        $oldhash = Get-FileHash $PROFILE
#        Invoke-RestMethod $url -OutFile "$env:temp/Microsoft.PowerShell_profile.ps1"
#        $newhash = Get-FileHash "$env:temp/Microsoft.PowerShell_profile.ps1"
#        if ($newhash.Hash -ne $oldhash.Hash) {
#            Copy-Item -Path "$env:temp/Microsoft.PowerShell_profile.ps1" -Destination $PROFILE -Force
#            Write-Host "Profile has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
#        }
#    } catch {
#        Write-Error "Unable to check for `$profile updates"
#    } finally {
#        Remove-Item "$env:temp/Microsoft.PowerShell_profile.ps1" -ErrorAction SilentlyContinue
#    }
#}
#Update-Profile

# Quick shortcut to start notepad
#function n { notepad $args }


# Ensure `editor` is installed and accessible
#if (Test-CommandExists 'notepad++') {
#    $env:EDITOR = "C:\Program Files\Notepad++\notepad++.exe"
#} else {
#    Write-Host "Notepad++ not found. Falling back to 'notepad'."
#    $env:EDITOR = "notepad"
#}

# Progress Bar Custom Colors

# Define a function to get the ANSI escape code for a given 256 color code
#function Get-256ColorCode {
#    param (
#        [int]$colorCode
#    )
#    return "`e[38;5;${colorCode}"
#}

# Define the color transition sequence (e.g., blue to red to white)
#$colors = @(27, 33, 39, 45, 51, 87, 123, 159, 195, 187, 186, 185, 184, 228, 227, 226, 221, 220, 179, 178, 136, 137, 173, 172, 215, 214, 209, 167, 208, 166, 202,203, 204, 162, 161, 125, 197, 160, 124, 196) # Adjust as necessary for a smooth transition

# Clear the console
#Clear-Host

#for ($i = 0; $i -le 100; $i++) {
#    $colorIndex = [math]::Round(($i / 100) * ($colors.Count - 1))
#    $colorCode = $colors[$colorIndex]
#    $color = Get-256ColorCode $colorCode
#    $activity = "${color}HotStuff${colorReset}"
#    $status = "${color}$i%Burnin'${colorReset}"
#    Write-Progress -Activity $activity -Status $status -PercentComplete $i
#    Start-Sleep -Milliseconds 100
#}

# Clear the progress bar
#Write-Progress -Activity "Complete" -Status "One Burn Down" -Completed

#######################
#END OLD STUFF
#######################

# Import the ChocolateyProfile that contains the necessary code to eable
# tab-completions to function for `choco`.
# Be aware that if you are missing these lines from your profile, tab completion
# for `choco` will not function.
# See https://ch0.co/tab-completion for details.
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

#Write-Host "EDITOR is set to: $env:EDITOR"

oh-my-posh init pwsh --config https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/kali.omp.json | Invoke-Expression

# Ensure Zoxide is initialized if available, or install it if not
if (Get-Command zoxide -ErrorAction SilentlyContinue) {
    if (-not (Get-Variable -Name __zoxide_hooked -ErrorAction SilentlyContinue)) {
        $global:__zoxide_hooked = $false
    }
    if (-not $global:__zoxide_hooked) {
        Invoke-Expression (& { (zoxide init powershell | Out-String) })
        $global:__zoxide_hooked = $true
    }
}
else {
    Write-Host "zoxide command not found. Attempting to install via winget..."
    try {
        winget install -e --id ajeetdsouza.zoxide -h
        Write-Host "zoxide installed successfully. Initializing..."
        if (-not (Get-Variable -Name __zoxide_hooked -ErrorAction SilentlyContinue)) {
            $global:__zoxide_hooked = $false
        }
        if (-not $global:__zoxide_hooked) {
            Invoke-Expression (& { (zoxide init powershell | Out-String) })
            $global:__zoxide_hooked = $true
        }
    }
    catch {
        Write-Error "Failed to install zoxide. Error: $_"
    }
}

