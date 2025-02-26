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
    
    if (-not (Test-Path -Path ('{0}\PackageManagement\ProviderAssemblies\NuGet\{1}' -f $env:ProgramFiles, $NuGetProviderVersion))) {
        [System.IO.DirectoryInfo] $NuGetProviderDirectory = New-Item @NuGetProviderDirectoryParameters
    } else {
        [System.IO.DirectoryInfo] $NuGetProviderDirectory = Get-Item -Path ('{0}\PackageManagement\ProviderAssemblies\NuGet\{1}' -f $env:ProgramFiles, $NuGetProviderVersion)
    }

    $providerDllPath = '{0}\Microsoft.PackageManagement.NuGetProvider.dll' -f $NuGetProviderDirectory.FullName
    if (-not (Test-Path -Path $providerDllPath)) {
        [hashtable] $NuGetProviderDownloadParameters = @{
            Uri     = $NuGetProviderDownloadUrl
            OutFile = $providerDllPath
        }
        $null = Invoke-WebRequest @NuGetProviderDownloadParameters
    }

    $null = Import-PackageProvider -Name 'NuGet' -Force

    Write-Output "$(Get-Date): Registering NuGet package source via Artifactory..."
    
    $pkgSourceExists = Get-PackageSource -Name 'NuGet-Artifactory' -ErrorAction SilentlyContinue
    if (-not $pkgSourceExists) {
        [hashtable] $PackageSourceParameters = @{
            Name           = 'NuGet-Artifactory'
            Location       = '{0}/artifactory/api/nuget/nuget-remote' -f $ArtifactoryUrl
            ProviderName   = 'NuGet'
            Trusted        = $true
            Force          = $true
            ForceBootstrap = $true
        }
        $null = Register-PackageSource @PackageSourceParameters
    } else {
        Write-Output "$(Get-Date): Package source 'NuGet-Artifactory' already exists, skipping registration."
    }

    Write-Output "$(Get-Date): Registering PowerShell repository via Artifactory..."
    $repoExists = Get-PSRepository -Name 'ArtifactoryPSGallery' -ErrorAction SilentlyContinue
    if (-not $repoExists) {
        [hashtable] $RepositoryParameters = @{
            Name                      = 'ArtifactoryPSGallery'
            SourceLocation            = '{0}/artifactory/api/nuget/psgallery-nuget-remote' -f $ArtifactoryUrl
            PublishLocation           = '{0}/artifactory/api/nuget/psgallery-nuget-remote/package/' -f $ArtifactoryUrl
            ScriptSourceLocation      = '{0}/artifactory/api/nuget/psgallery-nuget-remote/items/psscript' -f $ArtifactoryUrl
            ScriptPublishLocation     = '{0}/artifactory/api/nuget/psgallery-nuget-remote/package/' -f $ArtifactoryUrl
            InstallationPolicy        = 'Trusted'
            PackageManagementProvider = 'NuGet'
        }
        $null = Register-PSRepository @RepositoryParameters
    } else {
        Write-Output "$(Get-Date): PS Repository 'ArtifactoryPSGallery' already exists, skipping registration."
    }

    Write-Output "$(Get-Date): NuGet provider installed and repositories registered via Artifactory."
}
catch {
    if ($_.Exception.Message -like "*Repository*exists*") {
        Write-Output "$(Get-Date): Repository already exists, continuing."
    } else {
        Write-Output "$(Get-Date): Error configuring Artifactory as a NuGet/PSGallery proxy - $($_.Exception.Message)"
        throw $_.Exception
    }
}

try {
    Write-Output "$(Get-Date): Installing Az module from Artifactory..."
    if (-not (Get-Module -ListAvailable -Name Az)) {
        Install-Module Az -Repository 'ArtifactoryPSGallery' -Scope AllUsers -Force -AllowClobber
        Write-Output "$(Get-Date): Az module installed successfully."
    } else {
        Write-Output "$(Get-Date): Az module is already installed, skipping installation."
    }
    
    Import-Module Az.Accounts -Force

    Connect-AzAccount -Identity

    Write-Output "$(Get-Date): Az module imported successfully."
}
catch {
    if ($_.Exception.Message -like "*Module*exists*" -or $_.Exception.Message -like "*already installed*") {
        Write-Output "$(Get-Date): Az module already exists, continuing."
    } else {
        Write-Output "$(Get-Date): Error with Az module - $($_.Exception.Message)"
        throw $_.Exception
    }
}

try {
    Write-Output "$(Get-Date): Downloading MVP_Export.zip from Azure Storage..."
    if (-not (Test-Path -Path "C:\Temp\MVP_Export.zip")) {
        $ctx = New-AzStorageContext -StorageAccountName $StorageName
        Get-AzStorageBlobContent -Blob 'MVP_Export.zip' -Container 'scripts' -Destination 'C:\Temp' -Context $ctx
        Write-Output "$(Get-Date): Download completed."
    } else {
        Write-Output "$(Get-Date): MVP_Export.zip already exists, skipping download."
    }
    
    if (-not (Test-Path -Path "C:\Temp\MVP_Export")) {
        Write-Output "$(Get-Date): Extracting ZIP..."
        Expand-Archive -Path "C:\Temp\MVP_Export.zip" -DestinationPath "C:\Temp" -Force
        Write-Output "$(Get-Date): ZIP extracted successfully."
    } else {
        Write-Output "$(Get-Date): ZIP already extracted, skipping extraction."
    }
}
catch {
    if ($_.Exception.Message -like "*already exists*") {
        Write-Output "$(Get-Date): File already exists, continuing."
    } else {
        Write-Output "$(Get-Date): Error downloading or extracting ZIP - $($_.Exception.Message)"
        throw $_.Exception
    }
}

try {
    Write-Output "$(Get-Date): Installing AD-Domain-Services and DNS."
    $addsFeature = Get-WindowsFeature -Name AD-Domain-Services
    if (-not $addsFeature.Installed) {
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -Confirm:$false
        Write-Output "$(Get-Date): AD-Domain-Services installed successfully."
    } else {
        Write-Output "$(Get-Date): AD-Domain-Services already installed, skipping installation."
    }
    
    $dnsFeature = Get-WindowsFeature -Name DNS
    if (-not $dnsFeature.Installed) {
        Install-WindowsFeature -Name DNS -IncludeManagementTools -Confirm:$false
        Write-Output "$(Get-Date): DNS installed successfully."
    } else {
        Write-Output "$(Get-Date): DNS already installed, skipping installation."
    }
    
    Start-Sleep -Seconds 30
    
    $currentForwarders = Get-DnsServerForwarder -ErrorAction SilentlyContinue
    if (-not ($currentForwarders.IPAddress -contains [System.Net.IPAddress]"168.63.129.16")) {
        Set-DnsServerForwarder -IPAddress "168.63.129.16" -PassThru
        Write-Output "$(Get-Date): DNS forwarder set successfully."
    } else {
        Write-Output "$(Get-Date): DNS forwarder already set correctly, skipping configuration."
    }
} catch {
    if ($_.Exception.Message -like "*already installed*") {
        Write-Output "$(Get-Date): Feature already installed, continuing."
    } else {
        Write-Output "$(Get-Date): Error with AD and DNS - $($_.Exception.Message)"
        throw $_.Exception
    }
}

try {
    Write-Output "$(Get-Date): Starting Domain Controller Installation."
    $isDC = $false
    try {
        $isDC = (Get-ADDomainController -ErrorAction SilentlyContinue) -ne $null
    } catch {
        $isDC = $false
    }
    
    if (-not $isDC) {
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
    } else {
        Write-Output "$(Get-Date): This server is already a domain controller, skipping installation."
    }
} catch {
    if ($_.Exception.Message -like "*already a domain controller*") {
        Write-Output "$(Get-Date): Server is already a domain controller, continuing."
    } else {
        Write-Output "$(Get-Date): Error installing Domain Controller - $($_.Exception.Message)"
        throw $_.Exception
    }
}

try {
    Write-Output "$(Get-Date): Scheduling reboot in 1 minute."
    $time = (Get-Date).AddMinutes(1).ToString("HH:mm")
    schtasks /Create /TN "DelayedReboot" /SC ONCE /ST $time /RU SYSTEM /TR "powershell -command Restart-Computer -Force" /F
    Write-Output "$(Get-Date): Reboot scheduled successfully."
} catch {
    if ($_.Exception.Message -like "*task already exists*") {
        Write-Output "$(Get-Date): Reboot task already exists, continuing."
    } else {
        Write-Output "$(Get-Date): Error scheduling reboot - $($_.Exception.Message)"
        throw $_.Exception
    }
}

Write-Output "$(Get-Date): Script execution completed."
Stop-Transcript
exit 0
