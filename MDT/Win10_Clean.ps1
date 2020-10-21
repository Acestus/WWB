reg load HKLM\DEFAULT c:\users\default\ntuser.dat
 
# Advertising ID
reg add "HKLM\DEFAULT\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
 
#Delivery optimization, disabled
reg add "HKLM\DEFAULT\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v SystemSettingsDownloadMode /t REG_DWORD /d 3 /f
 
# Show titles in the taskbar
reg add "HKLM\DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarGlomLevel /t REG_DWORD /d 1 /f
 
# Hide system tray icons
reg add "HKLM\DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer" /v EnableAutoTray /t REG_DWORD /d 1 /f
 
# Show known file extensions
reg add "HKLM\DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f
 
# Show hidden files
#reg add "HKLM\DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
 
# Change default explorer view to my computer
reg add "HKLM\DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f
 
# Disable most used apps from appearing in the start menu
#reg add "HKLM\DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d 0 /f
 
# Remove search bar and only show icon
reg add "HKLM\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 1 /f
 
# Show Taskbar on one screen
#reg add "HKLM\DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v MMTaskbarEnabled /t REG_DWORD /d 0 /f
 
# Disable Security and Maintenance Notifications
#reg add "HKLM\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v Enabled /t REG_DWORD /d 0 /f
 
# Hide Windows Ink Workspace Button
reg add "HKLM\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" /v PenWorkspaceButtonDesiredVisibility /t REG_DWORD /d 0 /f
 
# Disable Game DVR
reg add "HKLM\DEFAULT\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f
 
# Show ribbon in File Explorer
reg add "HKLM\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" /v MinimizedStateTabletModeOff /t REG_DWORD /d 0 /f
 
# Hide Taskview button on Taskbar
reg add "HKLM\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f
 
# Hide People button from Taskbar
reg add "HKLM\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /t REG_DWORD /d 0 /f
 
# Hide Edge button in IE
reg add "HKLM\DEFAULT\SOFTWARE\Microsoft\Internet Explorer\Main" /v HideNewEdgeButton /t REG_DWORD /d 1 /f
 
# Remove OneDrive Setup from the RUN key
reg delete "HKLM\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSetup /F
 
reg unload HKLM\DEFAULT


#Disable Wi-Fi Sense
Write-Host "Disabling Wi-Fi Sense..."
If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
    New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
 
 
#Disable Bing Search in Start Menu
Write-Host "Disabling Bing Search in Start Menu..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
 
 
#Disable Start Menu suggestions
Write-Host "Disabling Start Menu suggestions..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0

#Disable Location Tracking
Write-Host "Disabling Location Tracking..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
 
#Disable Feedback
Write-Host "Disabling Feedback..."
If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
    New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
 
#Disable Advertising ID
Write-Host "Disabling Advertising ID..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
 


#Disable Cortana
Write-Host "Disabling Cortana..."
If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
    New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization")) {
    New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
    New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0

#Restrict Windows Update P2P only to local network
Write-Host "Restricting Windows Update P2P only to local network..."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value 3

 
#Stop and disable Diagnostics Tracking Service
Write-Host "Stopping and disabling Diagnostics Tracking Service..."
Stop-Service "DiagTrack"
Set-Service "DiagTrack" -StartupType Disabled



#Stop and disable WAP Push Service
Write-Host "Stopping and disabling WAP Push Service..."
Stop-Service "dmwappushservice"
Set-Service "dmwappushservice" -StartupType Disabled
  
 

#Service Tweaks

 

#Stop and disable Home Groups services
Write-Host "Stopping and disabling Home Groups services..."
Stop-Service "HomeGroupListener"
Set-Service "HomeGroupListener" -StartupType Disabled
Stop-Service "HomeGroupProvider"
Set-Service "HomeGroupProvider" -StartupType Disabled
 
#Disable Remote Assistance
Write-Host "Disabling Remote Assistance..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0

 
#Enable Remote Desktop w/o Network Level Authentication
Write-Host "Enabling Remote Desktop w/o Network Level Authentication..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0
 
 
 

#UI Tweaks

 
 
#Disable Autoplay
Write-Host "Disabling Autoplay..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1


#Disable Autorun for all drives
Write-Host "Disabling Autorun for all drives..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
 
 
#Disable Sticky keys prompt
Write-Host "Disabling Sticky keys prompt..." 
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
 
 

#Hide Search button / box
Write-Host "Hiding Search Box / Button..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
 
#Hide Task View button
Write-Host "Hiding Task View button..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
 
#Show titles in taskbar
Write-Host "Showing titles in taskbar..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1
 
 
#Show known file extensions
Write-Host "Showing known file extensions..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

 
#Change default Explorer view to "Computer"
Write-Host "Changing default Explorer view to `"Computer`"..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

 
 # Creating an array of bloatware apps to remove from Windows 10
$AppXApps = @(
    #Unnecessary Windows 10 AppX Apps
    "*Microsoft.BingNews*"
    "*Microsoft.GetHelp*"
    "*Microsoft.Getstarted*"
    "*Microsoft.Messaging*"
    "*Microsoft.Microsoft3DViewer*"
    "*Microsoft.MicrosoftOfficeHub*"
    #"*Microsoft.MicrosoftSolitaireCollection*"
    "*Microsoft.NetworkSpeedTest*"
    "*Microsoft.Office.Sway*"
    "*Microsoft.OneConnect*"
    "*Microsoft.People*"
    "*Microsoft.Print3D*"
    "*Microsoft.SkypeApp*"
    "*Microsoft.WindowsAlarms*"
    "*Microsoft.WindowsCamera*"
    "*microsoft.windowscommunicationsapps*"
    "*Microsoft.WindowsFeedbackHub*"
    "*Microsoft.WindowsMaps*"
    "*Microsoft.WindowsSoundRecorder*"
    "*Microsoft.Xbox.TCUI*"
    "*Microsoft.XboxApp*"
    "*Microsoft.XboxGameOverlay*"
    "*Microsoft.XboxIdentityProvider*"
    "*Microsoft.XboxSpeechToTextOverlay*"
    "*Microsoft.ZuneMusic*"
    "*Microsoft.ZuneVideo*"
    "*Microsoft.Office.OneNote*"
    "*Microsoft.Office.Desktop*"
    "*Microsoft.DesktopAppInstaller*"
    "*DellInc.DellSupportAssistforPCs*"
    "*DellInc.DellDigitalDelivery*"
    "*DellInc.DellCommandUpdate*"
    "*Microsoft.BingWeather*"

    # Sponsored/featured Windows 10 AppX Apps to remove in the "*AppName*" format
    "*EclipseManager*"
    "*ActiproSoftwareLLC*"
    "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
    "*Duolingo-LearnLanguagesforFree*"
    "*PandoraMediaInc*"
    "*CandyCrush*"
    "*Wunderlist*"
    "*Flipboard*"
    "*Twitter*"
    "*Facebook*"
    "*Spotify*"

    # Optional: Typically not removed but you can if you need to for some reason
    #"*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
    #"*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
    #"*Microsoft.MSPaint*"
    #"*Microsoft.MicrosoftStickyNotes*"
    #"*Microsoft.Windows.Photos*"
    #"*Microsoft.WindowsCalculator*"
    #"*Microsoft.WindowsStore*"
)

# Loop through the apps listed above and remove them from Windows 10.
foreach ($App in $AppXApps) {
    Write-Verbose -Message ('Removing Package {0}' -f $App)
    Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}

Write-Host "Remove bloatware script has been run"
  
#Uninstall default bloatware
Write-Host "Uninstalling default bloatware..."
Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage
Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage
Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage 
 
#Disable Xbox DVR
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0

Function clear-UserProfiles
<#
.Parameter ComputerName
The computer on which to clean profiles.

.Parameter AgeLimit
All profiles older than this number of days will be removed

.Parameter Exclude
Comma separt
#>
{
  [CmdletBinding(
     SupportsShouldProcess=$true,
    ConfirmImpact="High"
  )]param ($computerName= '.',$AgeLimit='180', $Exclude)

  $dateLimit = (get-date).adddays(-1 * $agelimit)
  $userprofiles = Get-WmiObject -Class Win32_UserProfile -ComputerName $computerName

  #the default exclusion list will prevent deletion of Administrator acount, Default accounts, System and Network Service
  $exclusionlist = @('S-1-5-19','S-1-5-18','S-1-5-20','-500$') + $Exclude | where-object {$_}

  foreach ($profile in $userprofiles) {
    #Check if profile is in date range
    $dateLastUsed = [datetime]::ParseExact(($profile.lastusetime -replace '\..+$',''),'yyyyMMddHHmmss',$null )
    if ( $dateLastused -ge $dateLimit){
        write-verbose "Skipping $($profile.sid) because it was last used $dateLastUsed"
        continue;    
    }

    #Check if profile matches an exclusion
    $MatchesExclusion = $false
    foreach ($comparison in $exclusionlist){
        if ($profile.sid -match $comparison -or $profile.localpath -match $comparison)
        {
            $MatchesExclusion = $true
            write-verbose "Skipping $($profile.sid) because it matches exclusion '$comparison'"
            break;
        }
    }
    if ($MatchesExclusion) {continue;}
    
    #Use ShouldProcess to prevent accidental removal of profiles
    $activity = "Remove profile for user $($profile.SID) from computer $Computername with local path $($profile.localpath)"
    if ($pscmdlet.ShouldProcess($activity)) {
        Write-Verbose "Attempting to $activity"
        $profile.Delete()       
    }
  }
}




#Restart
#Restart-Computer

