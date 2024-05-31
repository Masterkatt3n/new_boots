### PowerShell template profile 
### Version 1.03 - Tim Sneath <tim@sneath.org>
### From https://gist.github.com/timsneath/19867b12eee7fd5af2ba

# Initial GitHub.com connectivity check with 1 second timeout
$canConnectToGitHub = Test-Connection github.com -Count 1 -Quiet -TimeoutSeconds 1

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

# Check for Profile Updates
function Update-Profile {
    if (-not $global:canConnectToGitHub) {
        Write-Host "Skipping profile update check due to GitHub.com not responding within 1 second." -ForegroundColor Yellow
        return
    }

    try {
        $url = "https://raw.githubusercontent.com/Masterkatt3n/new_boots/main/PowerShell-profile.ps1"
        $oldhash = Get-FileHash $PROFILE
        Invoke-RestMethod $url -OutFile "$env:temp/Microsoft.PowerShell_profile.ps1"
        $newhash = Get-FileHash "$env:temp/Microsoft.PowerShell_profile.ps1"
        if ($newhash.Hash -ne $oldhash.Hash)
        {
            Copy-Item -Path "$env:temp/Microsoft.PowerShell_profile.ps1" -Destination $PROFILE -Force
            Write-Host "Profile has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
        }
    } catch {
        Write-Error "Unable to check for `$profile updates"
    } finally {
        Remove-Item "$env:temp/Microsoft.PowerShell_profile.ps1" -ErrorAction SilentlyContinue
    }
}
Update-Profile

# Compute file hashes - useful for checking successful downloads 
function md5 { Get-FileHash -Algorithm MD5 $args }
function sha1 { Get-FileHash -Algorithm SHA1 $args }
function sha256 { Get-FileHash -Algorithm SHA256 $args }

# Quick shortcut to start notepad
#function n { notepad $args }

# Drive shortcuts
#function HKLM: { Set-Location HKLM: }
#function HKCU: { Set-Location HKCU: }
#function Env: { Set-Location Env: }

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
# Delete them to prevent cluttering up the user profile. 
Remove-Variable identity
Remove-Variable principal

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

function Test-CommandExists {
    param($command)
    $exists = $null -ne (Get-Command $command -ErrorAction SilentlyContinue)
    return $exists
}

# Editor Configuration
$EDITOR = if (Test-CommandExists notepad++) { 'notepad++' }
elseif (Test-CommandExists pvim) { 'pvim' }
elseif (Test-CommandExists vim) { 'vim' }
elseif (Test-CommandExists vi) { 'vi' }
elseif (Test-CommandExists vscodium) { 'vscodium' }
elseif (Test-CommandExists nvim) { 'nvim' }
elseif (Test-CommandExists sublime_text) { 'sublime_text' }
else { 'notepad' }

$env:EDITOR = "C:\Program Files\Notepad++\notepad++.exe"

Set-Alias -Name ff -Value Find-File

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

# Network
function Get-PubIP {
    (Invoke-WebRequest http://ifconfig.me/ip ).Content
}
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
# Enhanced Listing
function la { Get-ChildItem -Path . -Force | Format-Table -AutoSize }
function ll { Get-ChildItem -Path . -Force -Hidden | Format-Table -AutoSize } 

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
function Find-File($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "$($_.directory)/$($_)"
    }
}
function unzip {
    param (
        [string]$source,
        [string]$destination = $PWD
    )

    Write-Output "Extracting $source to $destination"

    # Check if the source file exists
    $fullPath = Join-Path $PWD $source
    if (-not (Test-Path $fullPath -PathType Leaf)) {
        Write-Host "Source file not found: $fullPath" -ForegroundColor Red
        return
    }

    # Check if the destination folder exists, create it if not
    if (-not (Test-Path $destination -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $destination | Out-Null
    }

    # Unzip the contents
    try {
        Compress-Archive -Path $fullPath -DestinationPath $destination -Force -ErrorAction Stop
        Write-Output "Extraction successful"
    }
    catch {
        Write-Host "Extraction failed: $_" -ForegroundColor Red
    }
}
function ix ($file) {
    curl.exe -F "f:1=@$file" ix.io
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
}# Create new/empty profile file if not exists
if (!(Test-Path -Path $PROFILE)) {
    New-Item -ItemType File -Path $PROFILE -Force
}

# Check if Notepad++ is installed
$notepadPlusPlusPath = "C:\Program Files\Notepad++\notepad++.exe"
if (Test-Path $notepadPlusPlusPath) {
    $EDITOR = $notepadPlusPlusPath
} else {
    $EDITOR = "notepad"
}

$env:EDITOR = $EDITOR

# Ensure `editor` is installed and accessible
if (Test-CommandExists 'notepad++') {
    $EDITOR = 'notepad++'
} else {
    # Fallback to another editor or install notepad++
    Write-Host "$EDITOR not found. Falling back to 'notepad'."
    $EDITOR = 'notepad'
}

Set-Alias -Name vscode -Value $EDITOR
Set-Alias -Name ep -Value $EDITOR

# Editing Profile Shortcuts
function Edit-Profile {
    & "$env:EDITOR" $PROFILE
}
function ep {
    & "$env:EDITOR" $PROFILE
}

function touch($file) {
    "" | Out-File $file -Encoding ASCII
}
function df {
    get-volume
}
function sed($file, $find, $replace) {
    (Get-Content $file).replace("$find", $replace) | Set-Content $file
}
function which($name) {
    Get-Command $name | Select-Object -ExpandProperty Definition
}
function export($name, $value) {
    set-item -force -path "env:$name" -value $value;
}
function pkill($name) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}
function pgrep($name) {
    Get-Process $name
}
function reboot {
    Restart-Computer -Force
}

# PSWindowsUpdate aliases
function gwu {
    get-windowsupdate -verbose
}
function iwu {
    install-windowsupdate -AcceptAll -Autoreboot -verbose
}
function dwu {
    download-windowsupdate -AcceptAll -Verbose
}
function wuh {
    get-WUHistory -last 25 
}
function wul {
    Get-WULastResults
}

# Game
function Get-ItemProbabilities {
    param (
        [double]$drawRate5Star = 0.05,
        [int]$numberOf5StarItems = 8,
        [int]$orbsPerPull = 15
    )

    # Calculate probability of getting a 5-star item
    function Calculate5StarProbability {
        param (
            [double]$drawRate,
            [int]$numberOfItems
        )

        $probability = $drawRate / $numberOfItems
        return $probability
    }

    $probability5Star = Calculate5StarProbability $drawRate5Star $numberOf5StarItems

    # Simulate attempts to get a 5-star item
    $cumulativeCost = 0
    $attempts = 0

    while ($true) {
        $attempts++
        $cumulativeCost += $orbsPerPull

        # Generate a random number with more precision
        $randomNumber = (Get-Random -Minimum 0 -Maximum 100) / 100

        if ($randomNumber -le $probability5Star) {
            # Successfully obtained a 5-star item
            Write-Host "Successfully obtained a 5-star item in $attempts attempts."
            Write-Host "Cumulative cost to get a 5-star item: $cumulativeCost orbs"
            break
        }
    }
}
function Get-Specific5StarItem {
    param (
        [double]$drawRate5Star = 0.05,
        [double]$drawRateSpecific5Star = 0.01, # Adjust this to the specific item's draw rate
        [int]$numberOf5StarItems = 8,
        [int]$numberOfSpecific5StarItems = 1, # Number of specific 5-star items
        [int]$orbsPerPull = 15
    )

    # Calculate probabilities of getting a 5-star item and the specific 5-star item
    function Calculate5StarProbabilities {
        param (
            [double]$drawRate,
            [double]$drawRateSpecific,
            [int]$numberOfItems,
            [int]$numberOfSpecificItems
        )

        $probability5Star = $drawRate / $numberOfItems
        $probabilitySpecific5Star = $drawRateSpecific * $probability5Star * $numberOfSpecificItems
        return $probability5Star, $probabilitySpecific5Star
    }

    $probability5Star, $probabilitySpecific5Star = Calculate5StarProbabilities $drawRate5Star $drawRateSpecific5Star $numberOf5StarItems $numberOfSpecific5StarItems

    # Simulate attempts to get a 5-star item and the specific 5-star item
    $cumulativeCost = 0
    $attempts = 0

    while ($true) {
        $attempts++
        $cumulativeCost += $orbsPerPull

        $randomNumber = (Get-Random -Minimum 0 -Maximum 100) / 100

        if ($randomNumber -le $probabilitySpecific5Star) {
            # Successfully obtained the specific 5-star item
            Write-Host "Successfully obtained the specific 5-star item in $attempts attempts."
            Write-Host "Cumulative cost to get the specific 5-star item: $cumulativeCost orbs"
            break
        }

        if ($randomNumber -le $probability5Star) {
            # Successfully obtained a generic 5-star item
            Write-Host "Successfully obtained a 5-star item (not the specific one) in $attempts attempts."
            Write-Host "Cumulative cost to get a 5-star item: $cumulativeCost orbs"
            break
        }
    }
}
# Quick Access to System Information
function sysinfo { Get-ComputerInfo }

# Networking Utilities
function flushdns { Clear-DnsClientCache }

# Clipboard Utilities
function cpy { Set-Clipboard $args[0] }

function pst { Get-Clipboard }

# Enhanced PowerShell Experience
Set-PSReadLineOption -Colors @{
    Command   = 'Yellow'
    Parameter = 'Green'
    String    = 'DarkCyan'
}

# Import the ChocolateyProfile that contains the necessary code to eable
# tab-completions to function for `choco`.
# Be aware that if you are missing these lines from your profile, tab completion
# for `choco` will not function.
# See https://ch0.co/tab-completion for details.
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

Write-Host "EDITOR is set to: $env:EDITOR"

## Final Line to set prompt #
oh-my-posh init pwsh --config https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/kali.omp.json | Invoke-Expression
if (Get-Command zoxide -ErrorAction SilentlyContinue) {
    Invoke-Expression (& { (zoxide init powershell | Out-String) })
}
else {
    Write-Host "zoxide command not found. Attempting to install via winget..."
    try {
        winget install -e --id ajeetdsouza.zoxide
        Write-Host "zoxide installed successfully. Initializing..."
        Invoke-Expression (& { (zoxide init powershell | Out-String) })
    }
    catch {
        Write-Error "Failed to install zoxide. Error: $_"
    }
}
