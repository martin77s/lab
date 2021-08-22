Configuration DC {

    [CmdletBinding()]

    param (
        [string] $DomainName,
        [PSCredential] $DomainCreds
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName xPendingReboot
    Import-DscResource -ModuleName StorageDsc
    Import-DscResource -ModuleName NetworkingDsc
    Import-DscResource -ModuleName xPSDesiredStateConfiguration

    node localhost {

        LocalConfigurationManager {
            RebootNodeIfNeeded   = $true
            AllowModuleOverwrite = $true
            ActionAfterReboot    = 'ContinueConfiguration'
        }

        $Features = @(
            'AD-Domain-Services',
            'RSAT-ADDS',
            'RSAT-AD-Tools',
            'RSAT-AD-PowerShell',
            'RSAT-Role-Tools',
            'RSAT-DNS-Server',
            'GPMC',
            'DNS'
        )

        $Features.ForEach( {
                Write-Verbose "`t - $_" -Verbose
                WindowsFeature "$_" {
                    Ensure = 'Present'
                    Name   = $_
                }
            } )

        File ADDSFolder {
            Ensure          = 'Present'
            Type            = 'Directory'
            DestinationPath = 'C:\ADDS'
        }

        File MdiLabFolder {
            Ensure          = 'Present'
            Type            = 'Directory'
            DestinationPath = 'C:\MDILab'
        }

        xADDomain CreateForest {
            DomainName                    = $DomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath                  = 'C:\ADDS\NTDS'
            LogPath                       = 'C:\ADDS\NTDS'
            SysvolPath                    = 'C:\ADDS\Sysvol'
            ForestMode                    = 'Win2008R2'
            DomainMode                    = 'Win2008R2'
            DependsOn                     = '[WindowsFeature]AD-Domain-Services', '[File]ADDSFolder'
        }

        script CreateADUsers {

            TestScript = {
                Test-Path -Path 'C:\MDILab\postDeploy.flag'
            }

            GetScript  = {
                @{Result = (Get-Content -Path 'C:\MDILab\postDeploy.flag') }
            }

            SetScript  = {
                Set-Content -Path 'C:\MDILab\postDeploy.flag' -Value (Get-Date -Format yyyy-MM-dd-HH-mm-ss-ff)

                # Store the user passwords as variables
                $SamiraASecurePass = ConvertTo-SecureString -String 'NinjaCat123' -AsPlainText -Force
                $ronHdSecurePass = ConvertTo-SecureString -String 'FightingTiger$' -AsPlainText -Force
                $jefflSecurePass = ConvertTo-SecureString -String 'Password$fun' -AsPlainText -Force
                $AATPService = ConvertTo-SecureString -String 'Password123!@#' -AsPlainText -Force

                # Create new AD user SamiraA and add her to the domain admins group
                New-ADUser -Name SamiraA -DisplayName "Samira Abbasi" -PasswordNeverExpires $true -AccountPassword $samiraASecurePass -Enabled $true
                Add-ADGroupMember -Identity "Domain Admins" -Members SamiraA

                # Create new AD user RonHD, create new Helpdesk SG, add RonHD to the Helpdesk SG
                New-ADUser -Name RonHD -DisplayName "Ron Helpdesk" -PasswordNeverExpires $true -AccountPassword $ronHdSecurePass -Enabled $true
                New-ADGroup -Name Helpdesk -GroupScope Global -GroupCategory Security
                Add-ADGroupMember -Identity "Helpdesk" -Members "RonHD"

                # Create new AD user JeffL
                New-ADUser -Name JeffL -DisplayName "Jeff Leatherman" -PasswordNeverExpires $true -AccountPassword $jefflSecurePass -Enabled $true

                # Take note of the "AATPService" user below which will be our service account for Defender for Identity.
                # Create new AD user Defender for Identity Service
                New-ADUser -Name AatpService -DisplayName "Azure ATP/ATA Service" -PasswordNeverExpires $true -AccountPassword $AATPService -Enabled $true
            }
            DependsOn  = '[xADDomain]CreateForest', '[File]MdiLabFolder'
        }
    }
}



Configuration VictimPC {

    [CmdletBinding()]

    param (
        [string] $DomainName,
        [PSCredential] $DomainCreds
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ComputerManagementDsc

    $ComputerName = $env:ComputerName
    $DomainName = Split-Path $DomainCreds.UserName

    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true and DHCPEnabled=true' | ForEach-Object {
        $_.InvokeMethod('ReleaseDHCPLease', $null)
        $_.InvokeMethod('RenewDHCPLease', $null)
    }

    node localhost {

        LocalConfigurationManager {
            RebootNodeIfNeeded   = $true
            AllowModuleOverwrite = $true
            ActionAfterReboot    = 'ContinueConfiguration'
        }

        $Features = @(
            'RSAT-AD-PowerShell',
            'Telnet-Client'
        )

        $Features.ForEach( {
                Write-Verbose "`t - $_" -Verbose
                WindowsFeature "$_" {
                    Ensure = 'Present'
                    Name   = $_
                }
            } )

        xWaitForADDomain WaitForDomain {
            DomainName       = $DomainName
            RetryCount       = 60
            RetryIntervalSec = 15
        }

        Computer DomainJoin {
            Name       = $ComputerName
            DomainName = $DomainName
            Credential = $DomainCreds
            DependsOn  = '[xWaitForADDomain]WaitForDomain'
        }

        File MdiLabFolder {
            Ensure          = 'Present'
            Type            = 'Directory'
            DestinationPath = 'C:\MDILab'
        }

        script CreateADUsers {

            TestScript = {
                Test-Path -Path 'C:\MDILab\postDeploy.flag'
            }

            GetScript  = {
                @{Result = (Get-Content -Path 'C:\MDILab\postDeploy.flag') }
            }

            SetScript  = {
                Set-Content -Path 'C:\MDILab\postDeploy.flag' -Value (Get-Date -Format yyyy-MM-dd-HH-mm-ss-ff)

                # Add JeffL to local Administrators group on VictimPC
                Add-LocalGroupMember -Group "Administrators" -Member "$DomainName\JeffL"

                # Add Helpdesk to local Administrators group on VictimPC
                Add-LocalGroupMember -Group "Administrators" -Member "$DomainName\Helpdesk"
            }
            DependsOn  = '[Computer]DomainJoin', '[File]MdiLabFolder'
        }

    }
}



Configuration AdminPC {

    [CmdletBinding()]

    param (
        [string] $DomainName,
        [PSCredential] $DomainCreds
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ComputerManagementDsc

    $ComputerName = $env:ComputerName
    $DomainName = Split-Path $DomainCreds.UserName

    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true and DHCPEnabled=true' | ForEach-Object {
        $_.InvokeMethod('ReleaseDHCPLease', $null)
        $_.InvokeMethod('RenewDHCPLease', $null)
    }

    node localhost {

        LocalConfigurationManager {
            RebootNodeIfNeeded   = $true
            AllowModuleOverwrite = $true
            ActionAfterReboot    = 'ContinueConfiguration'
        }

        $Features = @(
            'RSAT-AD-PowerShell',
            'Telnet-Client'
        )

        $Features.ForEach( {
                Write-Verbose "`t - $_" -Verbose
                WindowsFeature "$_" {
                    Ensure = 'Present'
                    Name   = $_
                }
            } )

        xWaitForADDomain WaitForDomain {
            DomainName       = $DomainName
            RetryCount       = 60
            RetryIntervalSec = 15
        }

        Computer DomainJoin {
            Name       = $ComputerName
            DomainName = $DomainName
            Credential = $DomainCreds
            DependsOn  = '[xWaitForADDomain]WaitForDomain'
        }

        File MdiLabFolder {
            Ensure          = 'Present'
            Type            = 'Directory'
            DestinationPath = 'C:\MDILab'
        }

        script CreateADUsers {

            TestScript = {
                Test-Path -Path 'C:\MDILab\postDeploy.flag'
            }

            GetScript  = {
                @{Result = (Get-Content -Path 'C:\MDILab\postDeploy.flag') }
            }

            SetScript  = {
                Set-Content -Path 'C:\MDILab\postDeploy.flag' -Value (Get-Date -Format yyyy-MM-dd-HH-mm-ss-ff)

                # Add Helpdesk to local Administrators group
                Add-LocalGroupMember -Group "Administrators" -Member "Contoso\Helpdesk"

                # Remove Domain Admins from local Administrators group
                Remove-LocalGroupMember -Group "Administrators" -Member "Domain Admins"
            }
            DependsOn  = '[Computer]DomainJoin', '[File]MdiLabFolder'
        }

    }
}