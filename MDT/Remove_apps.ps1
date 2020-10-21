$AppsList = "Microsoft.3DBuilder","microsoft.windowscommunicationsapps","Microsoft.MicrosoftOfficeHub","Microsoft.SkypeApp","Microsoft.Getstarted","Microsoft.ZuneMusic","Microsoft.MicrosoftSolitaireCollection","Microsoft.ZuneVideo","Microsoft.Office.OneNote","Microsoft.People","Microsoft.XboxApp", "Microsoft.Messaging", "Microsoft.Microsoft3DViewer", "Microsoft.WindowsFeedbackHub", "Microsoft.GetHelp", "Microsoft.OneConnect"
ForEach ($App in $AppsList)
{
$PackageFullName = (Get-AppxPackage $App).PackageFullName
$ProPackageFullName = (Get-AppxProvisionedPackage -online | where {$_.Displayname -eq $App}).PackageName
write-host $PackageFullName
Write-Host $ProPackageFullName
if ($PackageFullName)
{
Write-Host “Removing Package: $App”
remove-AppxPackage -package $PackageFullName
}
else
{
Write-Host “Unable to find package: $App”
}
if ($ProPackageFullName)
{
Write-Host “Removing Provisioned Package: $ProPackageFullName”
Remove-AppxProvisionedPackage -online -packagename $ProPackageFullName
}
else
{
Write-Host “Unable to find provisioned package: $App”
}
}