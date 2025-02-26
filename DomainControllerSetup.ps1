[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$DomainName,
    [Parameter(Mandatory)] [string]$SafeModeAdministratorPassword,
    [Parameter(Mandatory)] [string]$DomainAdmincredsUserName,
    [Parameter(Mandatory)] [string]$DomainAdmincredsPassword,
    [Parameter(Mandatory)] [string]$Site,
    [Parameter(Mandatory)] [string]$StorageName,
    [Parameter(Mandatory)] [string]$ArtifactoryUrl
    

)

Start-Transcript -Path "C:\Temp\DomainControllerSetup.log" -Append
$ErrorActionPreference = 'Stop'
Write-Output "$(Get-Date): Script execution started."

try {
    Write-Output "$(Get-Date): Creating credentials."
    $SafeModeUsername = "Safemode"
    $SafeModePassword = ConvertTo-SecureString -AsPlainText $SafeModeAdministratorPassword -Force
    $SafeModeCred = New-Object System.Management.Automation.PSCredential ($SafeModeUsername, $SafeModePassword)

    $DomainUsername = "$DomainAdmincredsUserName@$DomainName"
    $DomainPassword = ConvertTo-SecureString -AsPlainText $DomainAdmincredsPassword -Force
    $DomainCred = New-Object System.Management.Automation.PSCredential ($DomainUsername, $DomainPassword)
    Write-Output "$(Get-Date): Credentials created successfully."
} catch {
    Write-Output "$(Get-Date): Error creating credentials - $($_.Exception.Message)"
    Stop-Transcript
    exit 1
}


try {
    Write-Output "$(Get-Date): Installing NuGet package provider from Artifactory..."

    [string] $NuGetProviderDownloadUrl = '{0}/artifactory/oneget-generic-remote/providers/Microsoft.PackageManagement.NuGetProvider-2.8.5.208.dll' -f $ArtifactoryUrl
    
    [version] $NuGetProviderVersion = ($NuGetProviderDownloadUrl -split 'Microsoft.PackageManagement.NuGetProvider-')[-1] -replace [regex]::new('^(\d+\.\d+\.\d+\.\d+)(.*)$'), '$1'

    [hashtable] $NuGetProviderDirectoryParameters = @{
        Path     = '{0}\PackageManagement\ProviderAssemblies\NuGet\{1}' -f $env:ProgramFiles, $NuGetProviderVersion
        ItemType = 'Directory'
        Force    = $true
    }
    [System.IO.DirectoryInfo] $NuGetProviderDirectory = New-Item @NuGetProviderDirectoryParameters

    [hashtable] $NuGetProviderDownloadParameters = @{
        Uri    = $NuGetProviderDownloadUrl
        OutFile = '{0}\Microsoft.PackageManagement.NuGetProvider.dll' -f $NuGetProviderDirectory.FullName
    }
    $null = Invoke-WebRequest @NuGetProviderDownloadParameters

    $null = Import-PackageProvider -Name 'NuGet' -Force

    Write-Output "$(Get-Date): Registering NuGet package source via Artifactory..."
    [hashtable] $PackageSourceParameters = @{
        Name              = 'NuGet-Artifactory'
        Location          = '{0}/artifactory/api/nuget/nuget-remote' -f $ArtifactoryUrl
        ProviderName      = 'NuGet'
        Trusted           = $true
        Force             = $true
        ForceBootstrap    = $true
    }
    $null = Register-PackageSource @PackageSourceParameters

    Write-Output "$(Get-Date): Registering PowerShell repository via Artifactory..."
    [hashtable] $RepositoryParameters = @{
        Name                     = 'ArtifactoryPSGallery'
        SourceLocation           = '{0}/artifactory/api/nuget/psgallery-nuget-remote' -f $ArtifactoryUrl
        PublishLocation          = '{0}/artifactory/api/nuget/psgallery-nuget-remote/package/' -f $ArtifactoryUrl
        ScriptSourceLocation     = '{0}/artifactory/api/nuget/psgallery-nuget-remote/items/psscript' -f $ArtifactoryUrl
        ScriptPublishLocation    = '{0}/artifactory/api/nuget/psgallery-nuget-remote/package/' -f $ArtifactoryUrl
        InstallationPolicy       = 'Trusted'
        PackageManagementProvider = 'NuGet'
    }
    $null = Register-PSRepository @RepositoryParameters

    Write-Output "$(Get-Date): NuGet provider installed and repositories registered via Artifactory."
}
catch {
    Write-Output "$(Get-Date): Error configuring Artifactory as a NuGet/PSGallery proxy - $($_.Exception.Message)"
    throw $_.Exception
}


try {
    Write-Output "$(Get-Date): Installing Az module from Artifactory..."
    Install-Module Az -Repository 'ArtifactoryPSGallery' -Scope AllUsers -Force -AllowClobber
    
    Import-Module Az.Accounts -Force

    Connect-AzAccount -Identity

    Write-Output "$(Get-Date): Az module installed and imported successfully."
}
catch {
    Write-Output "$(Get-Date): Error installing Az module - $($_.Exception.Message)"
    throw $_.Exception
}

try {
    Write-Output "$(Get-Date): Downloading MVP_Export.zip from Azure Storage..."
    $ctx = New-AzStorageContext -StorageAccountName $StorageName
    Get-AzStorageBlobContent -Blob 'MVP_Export.zip' -Container 'scripts' -Destination 'C:\Temp' -Context $ctx
    
    Write-Output "$(Get-Date): Download completed. Extracting ZIP..."
    Expand-Archive -Path "C:\Temp\MVP_Export.zip" -DestinationPath "C:\Temp"
    Write-Output "$(Get-Date): ZIP extracted successfully."
}
catch {
    Write-Output "$(Get-Date): Error downloading or extracting ZIP - $($_.Exception.Message)"
    throw $_.Exception
}

try {
    Write-Output "$(Get-Date): Installing AD-Domain-Services and DNS."
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -Confirm:$false
    Install-WindowsFeature -Name DNS -IncludeManagementTools -Confirm:$false
    Start-Sleep -Seconds 30
    Set-DnsServerForwarder -IPAddress "168.63.129.16" -PassThru
    Write-Output "$(Get-Date): AD and DNS installed successfully."
} catch {
    Write-Output "$(Get-Date): Error installing AD and DNS - $($_.Exception.Message)"
    throw $_.Exception
}



try {
    Write-Output "$(Get-Date): Starting Domain Controller Installation."
    Install-ADDSDomainController `
        -Credential $DomainCred `
        -SafeModeAdministratorPassword $($SafeModeCred.Password) `
        -NoGlobalCatalog:$false `
        -CreateDnsDelegation:$false `
        -CriticalReplicationOnly:$false `
        -DatabasePath "C:\Windows\NTDS" `
        -DomainName "$DomainName" `
        -InstallDns:$true `
        -LogPath "C:\Windows\NTDS" `
        -NoRebootOnCompletion:$true `
        -SysvolPath "C:\Windows\SYSVOL" `
        -Force:$true
    Write-Output "$(Get-Date): Finished DC Install. Scheduling reboot."
} catch {
    Write-Output "$(Get-Date): Error installing Domain Controller - $($_.Exception.Message)"
    throw $_.Exception
}

try {
    Write-Output "$(Get-Date): Scheduling reboot in 1 minute."
    $time = (Get-Date).AddMinutes(1).ToString("HH:mm")
    schtasks /Create /TN "DelayedReboot" /SC ONCE /ST $time /RU SYSTEM /TR "powershell -command Restart-Computer -Force" /F
    Write-Output "$(Get-Date): Reboot scheduled successfully."
} catch {
    Write-Output "$(Get-Date): Error scheduling reboot - $($_.Exception.Message)"
    throw $_.Exception
}

Write-Output "$(Get-Date): Script execution completed."
Stop-Transcript
exit 0
