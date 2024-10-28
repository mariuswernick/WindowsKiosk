 #=============================================================================================================================
#
# Script Name:     Deploy_AutoLogon_keyv.ps1
# Description:     Configure AutoLogon for specific users if not already correctly configured.
# Usage:           Intune PowerShell Platform Script
# Notes:           Ensure the KeyVault has the correct UPN and passwords.
# Version History:
# Version 1.0 - Initial release
# Contact Information:
# For any issues or questions, please contact Marius Wernick at marius.wernick@gmail.com
#=============================================================================================================================

# Install NuGet provider without interaction
Install-PackageProvider -Name NuGet -Force -Scope CurrentUser

# Install and import Az.KeyVault module without interaction
Install-Module -Name Az.KeyVault -Force -AllowClobber
Import-Module -Name Az.KeyVault

$azureAplicationId = "<APPID>"
$azureTenantId = "<TenantID>"
$azurePassword = ConvertTo-SecureString "<APPSECRET>" -AsPlainText -Force
$psCred = New-Object System.Management.Automation.PSCredential($azureAplicationId, $azurePassword)
Connect-AzAccount -Credential $psCred -TenantId $azureTenantId -ServicePrincipal

$secretNames = Get-AzKeyVaultSecret -VaultName '<VAULTNAME>' | Select-Object -ExpandProperty Name

$PackageName = "DeployAutologon"
Start-Transcript -Path "$Env:windir\Logs\Software\$PackageName-script.log" -Force

try {
    # Check if the Windows version is 11 or later
    $osVersion = [Environment]::OSVersion.Version
    $windows11Build = [Version] "10.0.22000.0"

    if ($osVersion -lt $windows11Build) {
        Write-Output "Windows version is not 11 or later. Stopping the Script."
        Exit 0
    }

    # Define the base registry path for autopilot pre provisioning
    $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"

    # Get all subkeys under the base path
    $subKeys = Get-ChildItem -Path $basePath

    # Initialize $currentUserEmail
    $currentUserEmail = $null

    foreach ($subKey in $subKeys) {
        # Get the UserEmail value for each subkey
        $userEmailValue = Get-ItemProperty -Path $subKey.PSPath -Name UserEmail -ErrorAction SilentlyContinue

        if ($userEmailValue) {
            # Print the UserEmail value
            Write-Output "Found UserEmail: $($userEmailValue.UserEmail) in key $($subKey.PSChildName)"
            $currentUserEmail = $userEmailValue.UserEmail.Trim()
            break
        }
    }

    # Output the current UserEmail for debugging purposes
    Write-Output "Current UserEmail: $currentUserEmail"

    if (-not $currentUserEmail) {
        Write-Output "No UserEmail found. Exiting script."
        Exit 1
    }

    # Extract the username part from the UserEmail
    $currentUsername = $currentUserEmail.Split('@')[0]
    Write-Output "Current Username: $currentUsername"

    # Retrieve password from Key Vault
    $passwordSecret = $null
    foreach ($name in $secretNames) {
        $trimmedName = $name.Trim()
        Write-Output "Comparing '$trimmedName' with '$currentUsername'"
        if ($trimmedName -ieq $currentUsername) {
            Write-Output "Match found: $trimmedName"
            $passwordSecret = Get-AzKeyVaultSecret -VaultName 'sikg-endpoint-prd-kv-wkp' -Name $trimmedName -AsPlainText
            break
        } else {
            Write-Output "No match: $trimmedName"
        }
    }

    if (-not $passwordSecret) {
        Write-Output "No matching secret found for the current user. Exiting script."
        Exit 1
    }

    # Define the registry path
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    # Get the current auto login settings from the registry
    $autoAdminLogon = Get-ItemProperty -Path $registryPath -Name "AutoAdminLogon" -ErrorAction SilentlyContinue
    $defaultUserName = Get-ItemProperty -Path $registryPath -Name "DefaultUserName" -ErrorAction SilentlyContinue
    $defaultPassword = Get-ItemProperty -Path $registryPath -Name "DefaultPassword" -ErrorAction SilentlyContinue

    # Check if auto login is enabled and if it needs remediation
    $remediate = $false

    if ($autoAdminLogon.AutoAdminLogon -ne "1" -or -not $defaultUserName -or -not $defaultPassword) {
        $remediate = $true
    } else {
        $configuredUser = $defaultUserName.DefaultUserName
        $configuredPassword = $defaultPassword.DefaultPassword

        if (-not ($configuredUser -eq $currentUserEmail -and $configuredPassword -eq $passwordSecret)) {
            $remediate = $true
        }
    }

    if ($remediate) {
        Write-Output "Remediating auto login configuration..."

        # Set the registry keys for auto login
        Set-ItemProperty -Path $registryPath -Name "AutoAdminLogon" -Value "1"
        Set-ItemProperty -Path $registryPath -Name "DefaultUserName" -Value $currentUserEmail
        Set-ItemProperty -Path $registryPath -Name "DefaultPassword" -Value $passwordSecret

        # Confirm the changes
        Write-Output "Auto login has been configured for user: $currentUserEmail"
    } else {
        Write-Output "Auto login is already correctly configured. No action taken."
    }
} catch {
    $errMsg = $_.Exception.Message
    Write-Error "An error occurred: $errMsg"
    Exit 1
} finally {
    Stop-Transcript
}
