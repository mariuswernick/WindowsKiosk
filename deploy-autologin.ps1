#=============================================================================================================================
#
# Script Name:     Deploy_AutoLogon.ps1
# Description:     Configure AutoLogon for specific users if not already correctly configured.
# Usage:           Intune PowerShell Platform Script
# Notes:           Ensure the UserMap has the correct UPN and passwords.
# Version History:
# Version 1.0 - Initial release
#
# Contact Information:
# For any issues or questions, please contact Marius Wernick at marius.wernick@gmail.com
#=============================================================================================================================
$Version=1

# Define the usernames and corresponding passwords
$UserMap = @{
    "anotheruser@domain.com" = @{ Password = "AnotherPassword123" }
    "anotheruser@domain.com" = @{ Password = "AnotherPassword123" }
    }

$PackageName="DeployAutologon"
Start-Transcript -Path "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\$PackageName-$Version-script.log" -Force

try {
    # Check if the Windows version is 11 or later
    $osVersion = [Environment]::OSVersion.Version
    $windows11Build = [Version] "10.0.22000.0"

    if ($osVersion -lt $windows11Build) {
        Write-Output "Windows version is not 11 or later. Stopping the Script."
        Exit 0
    }

    ##### Get the UPN 
    # Define the base registry path
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

    # Define the registry path
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    # Get the current auto login settings from the registry
    $autoAdminLogon = Get-ItemProperty -Path $registryPath -Name "AutoAdminLogon" -ErrorAction SilentlyContinue
    $defaultUserName = Get-ItemProperty -Path $registryPath -Name "DefaultUserName" -ErrorAction SilentlyContinue
    $defaultPassword = Get-ItemProperty -Path $registryPath -Name "DefaultPassword" -ErrorAction SilentlyContinue

    # Check if auto login is enabled and if it needs remediation
    $remediate = $false

    if ($autoAdminLogon.AutoAdminLogon -ne "1" -or $defaultUserName -eq $null -or $defaultPassword -eq $null) {
        $remediate = $true
    } else {
        $configuredUser = $defaultUserName.DefaultUserName
        $configuredPassword = $defaultPassword.DefaultPassword

        if (-not ($UserMap.ContainsKey($configuredUser) -and $UserMap[$configuredUser].Password -eq $configuredPassword)) {
            $remediate = $true
        }
    }

    if ($remediate) {
        Write-Output "Remediating auto login configuration..."

        if ($UserMap.ContainsKey($currentUserEmail)) {
            $userInfo = $UserMap[$currentUserEmail]
            $password = $userInfo.Password

            # Set the registry keys for auto login
            Set-ItemProperty -Path $registryPath -Name "AutoAdminLogon" -Value "1"
            Set-ItemProperty -Path $registryPath -Name "DefaultUserName" -Value $currentUserEmail
            Set-ItemProperty -Path $registryPath -Name "DefaultPassword" -Value $password

            # Confirm the changes
            Write-Output "Auto login has been configured for user: $currentUserEmail"
        } else {
            Write-Output "User $currentUserEmail not found in UserMap. Exiting script."
            Exit 1
        }
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
