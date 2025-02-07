#Requires -RunAsAdministrator
<#
.SYNOPSIS
    JEA Tool
.DESCRIPTION
    Configures Just Enough Administration (JEA) for user automation tools like BMC Discovery and ansible.
.AUTHOR
    M Ali
.VERSION
    1.2
#>

# Script metadata
$ScriptVersion = "1.2"
$LastUpdated = "2024"
$SAVELOG = 1  # Set to 1 to save logs, 0 to disable
$ScriptPath = $PSScriptRoot
$LogFile = Join-Path $ScriptPath "output.log"

# Predefined variables
$JEAUSER = "JeaUser"
$DefaultPassword = "P@ssw0rd123!@#"  # Complex password meeting requirements
$JEAPATH = "JEA"
$JEAGroup = "JEAGroup"
$JEAEndpoint = "JEAEndpoint"
$Author = "M Ali"
$CompanyName = "NA"
$JEADiscoveryCapabilities = "JEACapabilities"
$Description = "JEA role capabilities for RestrictedRemoteServer session type"
$WaitTime = 2  # Seconds to wait for operations to propagate

# ASCII Banner
function Show-Banner {
    $banner = @"
     _ _____    _    _____           _ 
    | | ____|  / \  |_   _|__   ___ | |
    | |  _|   / _ \   | |/ _ \ / _ \| |
 _  | | |___ / ___ \  | | (_) | (_) | |
|_|_|_|_____/_/   \_\ |_|\___/ \___/|_|

JEA Automation Tool                                       
Version: $ScriptVersion
By: x.com/MohamedNab1l

"@
    Write-Host $banner -ForegroundColor Cyan
}

# Check for admin privileges
function Test-AdminPrivileges {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Enhanced logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Type = "INFO",
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp][$Type] $Message"
    
    # Console output with colors
    if (-not $NoConsole) {
        switch ($Type) {
            "INFO"  { $color = "Green" }
            "WARN"  { $color = "Yellow" }
            "ERROR" { $color = "Red" }
            "DEBUG" { $color = "Cyan" }
            default { $color = "White" }
        }
        Write-Host $logMessage -ForegroundColor $color
    }

    # Save to log file if enabled
    if ($SAVELOG -eq 1) {
        try {
            Add-Content -Path $LogFile -Value $logMessage -ErrorAction Stop
        }
        catch {
            Write-Host "Failed to write to log file: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Initialize log file
function Initialize-Logging {
    if ($SAVELOG -eq 1) {
        try {
            $logHeader = @"
========================================
JEA Configuration Script Log
Version: $ScriptVersion
Started: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Computer: $env:COMPUTERNAME
User: $env:USERNAME
========================================

"@
            Set-Content -Path $LogFile -Value $logHeader -Force
            Write-Log "Log file initialized at: $LogFile" "DEBUG"
        }
        catch {
            Write-Log "Failed to initialize log file: $($_.Exception.Message)" "ERROR"
            exit 1
        }
    }
}
# Main script execution
try {
    Clear-Host
    Show-Banner
    Initialize-Logging

    Write-Log "Script execution started" "DEBUG"
    Write-Log "Running with following parameters:" "DEBUG"
    Write-Log "JEA User: $JEAUSER" "DEBUG"
    Write-Log "JEA Path: $JEAPATH" "DEBUG"
    Write-Log "JEA Group: $JEAGroup" "DEBUG"

    if (-not (Test-AdminPrivileges)) {
        Write-Log "This script requires administrative privileges." "ERROR"
        exit 1
    }

    Write-Log "Administrative privileges confirmed" "DEBUG"
    Write-Log "Starting JEA configuration..."

    # Create required directories
    Write-Log "Creating required directories..." "DEBUG"
    $paths = @(
        "C:\$JEAPATH\$JEADiscoveryCapabilities",
        "C:\$JEAPATH\JEADiscoverySessionConfiguration",
        "C:\$JEAPATH\JEADiscoveryTranscripts"
    )

    foreach ($path in $paths) {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -ItemType Directory -Force
            Write-Log "Created directory: $path"
        }
        else {
            Write-Log "Directory already exists: $path" "DEBUG"
        }
    }

    # User and Group Management
    Write-Log "Starting user and group management..." "DEBUG"
    
    # Create secure password
    $securePassword = ConvertTo-SecureString -String $DefaultPassword -AsPlainText -Force

    # Group Creation First
    try {
        $existingGroup = Get-LocalGroup -Name $JEAGroup -ErrorAction SilentlyContinue
        if (-not $existingGroup) {
            New-LocalGroup -Name $JEAGroup -Description "JEA User Group"
            Write-Log "Created local group: $JEAGroup" "INFO"
            Start-Sleep -Seconds $WaitTime  # Wait for group creation to propagate
        }
        else {
            Write-Log "Group $JEAGroup already exists" "DEBUG"
        }
    }
    catch {
        Write-Log "Failed to create group [$JEAGroup] - $($_.Exception.Message)" "ERROR"
        throw
    }

    # User Creation/Update
    try {
        $existingUser = Get-LocalUser -Name $JEAUSER -ErrorAction SilentlyContinue
        if ($existingUser) {
            Write-Log "User $JEAUSER already exists" "DEBUG"
            try {
                Set-LocalUser -Name $JEAUSER -Password $securePassword
                Write-Log "Updated password for existing user $JEAUSER" "DEBUG"
            }
            catch {
                Write-Log "Failed to update password for user [$JEAUSER] - $($_.Exception.Message)" "ERROR"
                throw
            }
        }
        else {
            $userParams = @{
                Name = $JEAUSER
                Password = $securePassword
                Description = "JEA User for Automation Tools"
                PasswordNeverExpires = $true
                UserMayNotChangePassword = $true
            }
            New-LocalUser @userParams
            Write-Log "Created local user: $JEAUSER" "INFO"
            Start-Sleep -Seconds $WaitTime  # Wait for user creation to propagate
        }
    }
    catch {
        Write-Log "Failed to create/update user [$JEAUSER] - $($_.Exception.Message)" "ERROR"
        throw
    }

    # Add User to Group
    try {
        $groupMembers = Get-LocalGroupMember -Group $JEAGroup -ErrorAction SilentlyContinue
        $userInGroup = $groupMembers | Where-Object { $_.Name -like "*\$JEAUSER" }
        
        if (-not $userInGroup) {
            $computerName = $env:COMPUTERNAME
            $fullUserName = "$computerName\$JEAUSER"
            
            Add-LocalGroupMember -Group $JEAGroup -Member $fullUserName
            Write-Log "Added $JEAUSER to $JEAGroup" "INFO"
            Start-Sleep -Seconds $WaitTime  # Wait for group membership to propagate
        }
        else {
            Write-Log "User $JEAUSER is already a member of $JEAGroup" "DEBUG"
        }
    }
    catch {
        Write-Log "Failed to add user to group - $($_.Exception.Message)" "ERROR"
        throw
    }

    # Create role capabilities file
    Write-Log "Creating role capabilities file..." "DEBUG"
    $RCHT = @{
        Path = "C:\$JEAPATH\$JEADiscoveryCapabilities\RestrictedRemoteServer.psrc"
        Author = $Author
        CompanyName = $CompanyName
        Description = $Description
        VisibleCmdlets = @(
            'Out-Default', 'Out-File', 'Get-FormatData', 'Exit-PSSession',
            'Get-Command', 'Measure-Object', 'Select-Object', 'Get-CimInstance',
            'ForEach-Object', 'Get-ItemProperty', 'Get-Item', 'New-Object',
            'Get-ChildItem', 'Test-Path', 'Get-SmbShare', 'Get-Module',
            'Import-Module', 'Get-NfsShare', 'Invoke-RestMethod',
            'Get-NetTCPConnection', 'Get-NetUDPEndpoint', 'Invoke-WmiMethod',
            'Select-String', 'Get-Content', 'Get-FileHash', 'Get-WmiObject',
            'Remove-Item', 'Split-Path'
        )
        VisibleExternalCommands = @('*.exe', '*.bat', '*.ps1', '*.cmd')
    }

    New-PSRoleCapabilityFile @RCHT
    Write-Log "Role capabilities file created successfully" "INFO"

    # Create session configuration
    Write-Log "Creating session configuration..." "DEBUG"
    $RDHT = @{
        "$JEAGroup" = @{
            'RoleCapabilityFiles' = "C:\$JEAPATH\$JEADiscoveryCapabilities\RestrictedRemoteServer.psrc"
        }
    }

    $PSCHT = @{
        Author = $Author
        Description = $Description
        SessionType = 'RestrictedRemoteServer'
        LanguageMode = 'FullLanguage'
        Path = "C:\$JEAPATH\JEADiscoverySessionConfiguration\Discovery.pssc"
        RunAsVirtualAccount = $true
        TranscriptDirectory = "C:\$JEAPATH\JEADiscoveryTranscripts"
        RoleDefinitions = $RDHT
    }

    New-PSSessionConfigurationFile @PSCHT
    Write-Log "Session configuration file created successfully" "INFO"

    # Test configuration file
    Write-Log "Testing session configuration file..." "DEBUG"
    if (-not (Test-PSSessionConfigurationFile -Path "C:\$JEAPATH\JEADiscoverySessionConfiguration\Discovery.pssc")) {
        throw "Session configuration file test failed"
    }
    Write-Log "Session configuration file test passed successfully" "INFO"

    # Enable PS Remoting
    Write-Log "Enabling PowerShell remoting..." "DEBUG"
    Enable-PSRemoting -Force -SkipNetworkProfileCheck
    Write-Log "PowerShell remoting enabled successfully" "INFO"

    # Handle existing endpoint
    if (Get-PSSessionConfiguration -Name $JEAEndpoint -ErrorAction SilentlyContinue) {
        Write-Log "Existing endpoint found, unregistering..." "DEBUG"
        Unregister-PSSessionConfiguration -Name $JEAEndpoint -Force
        Write-Log "Existing endpoint unregistered" "INFO"
        Start-Sleep -Seconds $WaitTime  # Wait for unregistration to complete
    }

    # Register PS Session Configuration
    Write-Log "Registering new PS Session Configuration..." "DEBUG"
    $registerResult = Register-PSSessionConfiguration -Path "C:\$JEAPATH\JEADiscoverySessionConfiguration\Discovery.pssc" `
        -Name $JEAEndpoint -Force -ErrorVariable registerError

    if ($registerError) {
        Write-Log "Warning during registration: $($registerError[0].Exception.Message)" "WARN"
        Write-Log "Attempting to verify registration..." "DEBUG"
        
        $endpoint = Get-PSSessionConfiguration -Name $JEAEndpoint -ErrorAction SilentlyContinue
        if ($endpoint) {
            Write-Log "Endpoint exists despite warning, proceeding..." "WARN"
        } else {
            throw "Failed to verify endpoint registration"
        }
    } else {
        Write-Log "PS Session Configuration registered successfully" "INFO"
    }

    # Restart WinRM
    Write-Log "Restarting WinRM service..." "DEBUG"
    Restart-Service WinRM -Force
    Start-Sleep -Seconds $WaitTime  # Wait for service to restart
    Write-Log "WinRM service restarted successfully" "INFO"

    Write-Log "JEA Configuration completed successfully" "INFO"
    Write-Log "To test, run: Enter-PSSession -ComputerName localhost -ConfigurationName $JEAEndpoint -Credential $JEAUSER" "INFO"

    if ($SAVELOG -eq 1) {
        Write-Log "Log file has been saved to: $LogFile" "DEBUG"
    }
}
catch {
    Write-Log "Critical error occurred: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    exit 1
}
