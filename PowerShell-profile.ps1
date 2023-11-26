### PowerShell template profile 
### Version 1.03 - Tim Sneath <tim@sneath.org>
### From https://gist.github.com/timsneath/19867b12eee7fd5af2ba

# Import Terminal Icons
Import-Module -Name Terminal-Icons

# Find out if the current user identity is elevated (has admin rights)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# If so and the current host is a command line, then change to red color 
# as a warning to the user that they are operating in an elevated context
# Useful shortcuts for traversing directories
function cd... { Set-Location ..\.. }
function cd.... { Set-Location ..\..\.. }

# Compute file hashes - useful for checking successful downloads 
function md5 { Get-FileHash -Algorithm MD5 $args }
function sha1 { Get-FileHash -Algorithm SHA1 $args }
function sha256 { Get-FileHash -Algorithm SHA256 $args }

# Quick shortcut to start notepad
function n { notepad $args }

# Drive shortcuts
function HKLM: { Set-Location HKLM: }
function HKCU: { Set-Location HKCU: }
function Env: { Set-Location Env: }

# Creates a drive shortcut for Work Folders if the current user account is using it
if (Test-Path "$env:USERPROFILE\Work Folders") {
    New-PSDrive -Name Work -PSProvider FileSystem -Root "$env:USERPROFILE\Work Folders" -Description "Work Folders"
    function Work: { Set-Location Work: }
}

# Set up the command prompt and window title. Use UNIX-style conventions for identifying 
# whether the user is elevated (root) or not. Window title shows the current version of PowerShell
# and appends [ADMIN] if appropriate for easy taskbar identification
function prompt { 
    $location = if ($isAdmin) { "[{0}] # " -f (Get-Location) } else { "[{0}] $ " -f (Get-Location) }
    Write-Output $location
}

$Host.UI.RawUI.WindowTitle = "PowerShell {0}" -f $PSVersionTable.PSVersion.ToString()
if ($isAdmin) {
    $Host.UI.RawUI.WindowTitle += " [ADMIN]"
}

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
        Start-Process -FilePath "$psHome\pwsh.exe" -Verb runAs -ArgumentList $argList
    } else {
        Start-Process -FilePath 'pwsh' -Verb runAs -ArgumentList $argList
    }
}

# Set UNIX-like aliases for the admin command, so sudo <command> will run the command
# with elevated rights. 
Set-Alias -Name su -Value admin
Set-Alias -Name sudo -Value admin

# Make it easy to edit this profile once it's installed
function Edit-Profile {
    if ($host.Name -match "ise") {
        $psISE.CurrentPowerShellTab.Files.Add($profile.CurrentUserAllHosts)
    } else {
        Start-Process $profile
    }
}

# We don't need these anymore; they were just temporary variables to get to $isAdmin. 
# Delete them to prevent cluttering up the user profile. 
Remove-Variable identity
Remove-Variable principal

function Test-CommandExists {
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try { if (Get-Command $command) { RETURN $true }}
    Catch { Write-Host "$command does not exist"}
    Finally { $ErrorActionPreference = $oldPreference }
} 

# Aliases
if (Test-CommandExists nvim) {
    $EDITOR='nvim'
} elseif (Test-CommandExists pvim) {
    $EDITOR='pvim'
} elseif (Test-CommandExists vim) {
    $EDITOR='vim'
} elseif (Test-CommandExists vi) {
    $EDITOR='vi'
} elseif (Test-CommandExists code) {
    $EDITOR='code'
} elseif (Test-CommandExists notepad) {
    $EDITOR='notepad'
} elseif (Test-CommandExists notepad++) {
    $EDITOR='notepad++'
} elseif (Test-CommandExists sublime_text) {
    $EDITOR='sublime_text'
}
Set-Alias -Name vim -Value $EDITOR
Set-Alias -Name ff -Value Find-File

function ll { Get-ChildItem -Path $pwd -File }
function g { Set-Location $HOME\Documents\Github }
function gcom {
    git add .
    git commit -m "$args"
}
function lazyg {
    git add .
    git commit -m "$args"
    git push
}
function Get-PubIP {
    (Invoke-WebRequest http://ifconfig.me/ip ).Content
}
function uptime {
    # Windows PowerShell only
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        Get-WmiObject win32_operatingsystem | Select csname, @{LABEL='LastBootUpTime'; 
                EXPRESSION={ $_.ConverttoDateTime($_.lastbootuptime)}} 
    } else {
        net statistics workstation | Select-String "sedan" | foreach-object {$_.ToString().Replace('Statistik sedan', '')}
        New-TimeSpan (Get-uptime -Since) | Select-Object -Property Days, Hours, Minutes, Seconds
    }
}
 
function reload-profile {
    . $PROFILE
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
function grep($regex, $dir) {
    if ($dir) {
        Get-ChildItem $dir | ForEach-Object {
            Get-Content $_.FullName | Select-String $regex
        }
    }
    else {
        Get-Content $regex | Select-String $regex  
    }
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

# Import the Chocolatey Profile that contains the necessary code to enable
# tab-completions to function for `choco`.
# Be aware that if you are missing these lines from your profile, tab completion
# for `choco` will not function.
# See https://ch0.co/tab-completion for details.
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

Invoke-Expression (& { (zoxide init powershell | Out-String) })

## Final Line to set prompt
oh-my-posh init pwsh --config https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/kali.omp.json | Invoke-Expression
