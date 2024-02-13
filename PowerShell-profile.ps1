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
} elseif (Test-CommandExists vscode) {
    $EDITOR='vscode'	
} elseif (Test-CommandExists notepad) {
    $EDITOR='notepad'
} elseif (Test-CommandExists notepad++) {
    $EDITOR='notepad++'
} elseif (Test-CommandExists sublime_text) {
    $EDITOR='sublime_text'
}
Set-Alias -Name nvim -Value $EDITOR
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
        Get-WmiObject win32_operatingsystem | Select-Object csname, @{LABEL='LastBootUpTime'; 
                EXPRESSION={ $_.ConverttoDateTime($_.lastbootuptime)}} 
    } else {
        net statistics workstation | Select-String "sedan" | foreach-object {$_.ToString().Replace('Statistik sedan', '')}
        New-TimeSpan (Get-uptime -Since) | Select-Object -Property Days, Hours, Minutes, Seconds
    }
}
 
function update-profile {
    Write-Host "Reloading profile..."
    Write-Host "Current execution policy: $(Get-ExecutionPolicy)"
    #Write-Host "Current profile location: $PROFILE"
    
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
        Write-Host "Error: $_"
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
function start-yatzy {
# Define a class for Dice
  class Dice {
      [int]$value

      Dice() {
          $this.value = Get-Random -Minimum 1 -Maximum 7
      }

      [int] getValue() {
          return $this.value
      }

      [void] roll() {
          $this.value = Get-Random -Minimum 1 -Maximum 7
      }
  } 

# Define a class for Player
  class Player {
      [string]$name
      [int[]]$score = @(-1) * 13

      Player([string]$n) {
          $this.name = $n
      }

      [string] getName() {
          return $this.name
      }

      [int] getScore([int]$category) {
          return $this.score[$category]
      }

      [void] setScore([int]$category, [int]$points) {
          $this.score[$category] = $points
      }

      [int] getTotalScore() {
          $total = 0
          foreach ($points in $this.score) {
              if ($points -ne -1) {
                  $total += $points
              }
          }
          return $total
      }
  }

  # Define a class for the game
  class Game {
      [Dice[]]$dice = @([Dice]::new()) * 5
      [Player[]]$players = @()
      [bool[]]$hold = @($false) * 5
      [int]$round = 0
      [int]$turn = 0

          Game([string]$n1, [string]$n2) {
        $this.players += [Player]::new($n1)
        $this.players += [Player]::new($n2)
        $this.dice = @()
        for ($i = 0; $i -lt 5; $i++) {
            $this.dice += [Dice]::new()
      }
  }


   [void] rollDice() {
    Write-Host "Rolling dice..."
    foreach ($i in 0..4) {
        Write-Host "Rolling die $i..."
        if (-not $this.hold[$i]) {
            $this.dice[$i].roll()
      }
  }
}


      [int] getDiceValue([int]$index) {
          return $this.dice[$index].getValue()
      }

      [void] chooseDice([int]$index) {
          $this.hold[$index] = -not $this.hold[$index]
      }

      [bool] isHeld([int]$index) {
          return $this.hold[$index]
      }

      [int] countScore([int]$category) {
          $points = 0
          [int[]]$count = @(0) * 6

          foreach ($die in $this.dice) {
              $count[$die.getValue() - 1]++
          }

          if ($category -ge 0 -and $category -le 5) {
              $points = $count[$category] * ($category + 1)
          }
          elseif ($category -eq 6) {
              for ($i = 5; $i -ge 0; $i--) {
                  if ($count[$i] -ge 2) {
                      $points = ($i + 1) * 2
                      break
                  }
              }
          }
          # Implement other categories similarly...

          return $points
      }
 }

# Example of usage

# number of tests
$trials = 100
$results = @()

# Run the simulation for the amount of tests
for ($i = 1; $i -le $trials; $i++) {
    $game = [Game]::new("Player1", "Player2")
    $game.rollDice()
    $results += $game.dice | ForEach-Object { $_.getValue() }
 }

# Output the results and count the values of each dice 
$results | Group-Object | Sort-Object Name | ForEach-Object {
    Write-Output "Dice value: $($_.Name), Count: $($_.Count)"
 }

# Output the total number of trials
Write-Output "Total trials: $trials"
}

# Example of usage

#$game = [Game]::new("Player1", "Player2")
#$game.rollDice()
#foreach ($die in $game.dice) {
#    Write-Host "Dice value: $($die.getValue())"
# }	 
#}

# Import the ChocolateyProfile that contains the necessary code to eable
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
