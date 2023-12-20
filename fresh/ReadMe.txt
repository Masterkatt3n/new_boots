A script to automize application and program installations, intended mostly for fresh Windows installations with a feature debloating most preinstalled apps.

The folder NEEDS to be placed in the root directory!!
If you have to create a new one, make sure to name it "fresh". If root isnt't "c:", the driveletter in install.ps1 needs to change accordingly.

Make changes or add to the list of applications in the install script and read both before running.

To get the Oh-My-Posh module to work properly, changes to the Font Settings need to be made in Windows Terminal. 
AutoHotkey is needed for Chocolatey to run , it's already in the lists of applications to download.  

Enter the settings by clicking the icon next to the "new tab" in the Terminal, or press <Crtl+,>.

In Defaults under the Profiles selection, enter Apperances in Additional settings.
Select any CaskaydiaCove Font to your liking in the Font face meny. I use "CaskaydiaCove Nerd Font Mono", click save and close the window. 
The visuals in the Terminal should be fixed when started up again.
If you wish to choose your own PoshTheme, enter the command <Get-PoshThemes> to browse all available in Powershell 7 when all is done. 
How to change themes can be found at the end inside the default PS-profile, and is also where to input the theme you chosen.  
Execute the script by rightclick install.ps1, "run with powershell". 


Thx to Chris Titus. 
https://christitus.com/
https://christitus.com/windows-tool/
https://christitus.com/pretty-powershell/


  
