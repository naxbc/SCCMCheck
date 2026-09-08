#Requires -Version 5.1
<#
.SYNOPSIS
    Scans SCCM (Microsoft Configuration Manager) site systems and roles, tests network
    port connectivity and validates SCCM-related Windows services, then displays the
    results in a pop-up dashboard.

.DESCRIPTION
    Connects to the SMS Provider (site server) via WMI/CIM and reads SMS_SCI_SysResUse
    to discover every site system server and the roles assigned to it. For each
    server/role it:
      - Pings the server
      - Tests the TCP ports normally associated with that role
      - Queries the state of the Windows services normally associated with that role
    It also explicitly checks the core SCCM services on the site server itself.

    Results are shown in a WinForms pop-up dashboard with color-coded health
    (Healthy / Warning / Critical), a status filter, CSV export, and a refresh button.
    Use -NoGui to print a console table instead (useful for scheduled tasks or when no
    interactive desktop session is available).

    Zero-configuration usage: run this single file directly on the SCCM site server with
    no parameters - right-click it and choose "Run with PowerShell" (which also bypasses
    the machine's execution policy automatically), or run it from an existing console
    with `.\SCCM-SiteSystemHealthDashboard.ps1`. It defaults to the local computer as the
    provider, auto-detects the site code, and enumerates every site system and role from
    there - nothing needs to be edited, and there is no separate launcher file. Checks
    against the local machine itself use local WMI directly (no remote CIM session),
    avoiding "Access is denied" failures some patched Windows Server builds throw when a
    machine connects to itself over DCOM. If the GUI is requested but the process isn't
    running single-threaded apartment (required by WinForms - Windows PowerShell is STA
    by default, but PowerShell 7's `pwsh` defaults to MTA), the script transparently
    relaunches itself with -STA so the dashboard still works with no extra steps.

    The role -> port and role -> service mappings in the CONFIGURATION section are
    best-effort defaults for a typical Configuration Manager hierarchy. Environments
    that use non-default ports (custom HTTPS bindings, WSUS on 80/443 instead of
    8530/8531, named SQL instances, etc.) can edit that section to match, but this is
    optional - the script runs unedited out of the box.

.PARAMETER ProviderMachineName
    The SMS Provider / site server to query for site system and role data. Defaults to
    the local computer name, so running the script on the site server itself needs no
    parameters at all.

.PARAMETER SiteCode
    The 3-character SCCM site code. If omitted, it is auto-detected from
    SMS_ProviderLocation on ProviderMachineName.

.PARAMETER Credential
    Optional credential to use for the remote WMI/CIM connections (site data query,
    service checks). Defaults to the current user's context.

.PARAMETER Protocol
    CIM protocol used for remote WMI queries: 'Dcom' (classic remote WMI over RPC,
    TCP 135 - default, matches the "SMS Provider access" ports most SCCM environments
    already have open) or 'Wsman' (WinRM).

.PARAMETER PortTimeoutMs
    Per-port TCP connect timeout in milliseconds. Default 1500.

.PARAMETER NoGui
    Skip the pop-up dashboard and print a formatted console table instead.

.PARAMETER ExportCsvPath
    If specified, results are also written to this CSV path regardless of -NoGui.

.EXAMPLE
    .\SCCM-SiteSystemHealthDashboard.ps1

    Run on the site server itself; auto-detects the site code and pops up the dashboard.

.EXAMPLE
    .\SCCM-SiteSystemHealthDashboard.ps1 -ProviderMachineName CM01 -SiteCode P01 -Credential (Get-Credential)

.EXAMPLE
    .\SCCM-SiteSystemHealthDashboard.ps1 -ProviderMachineName CM01 -NoGui -ExportCsvPath C:\Temp\sccm-health.csv
#>

[CmdletBinding()]
param(
    [string]$ProviderMachineName = $env:COMPUTERNAME,

    [string]$SiteCode,

    [System.Management.Automation.PSCredential]$Credential,

    [ValidateSet('Dcom', 'Wsman')]
    [string]$Protocol = 'Dcom',

    [int]$PortTimeoutMs = 1500,

    [switch]$NoGui,

    [string]$ExportCsvPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ================= self-relaunch in STA (WinForms requires it) =================

# WinForms requires a single-threaded apartment. Windows PowerShell (powershell.exe) is
# STA by default, but PowerShell 7's pwsh.exe defaults to MTA and would crash when the
# dashboard tries to open. Detect that case and transparently relaunch this same file
# with -STA so the script still "just works" with no separate launcher and no manual
# -STA flag to remember. Skipped entirely for -NoGui, which never touches WinForms.
if (-not $NoGui -and [System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA' -and $PSCommandPath) {
    Write-Host 'Relaunching in a single-threaded apartment (required for the GUI dashboard)...'
    # Start-Process -ArgumentList joins the array with plain spaces (no auto-quoting), so
    # every element that could itself contain a space must be quoted here explicitly.
    $relaunchArgs = @('-NoLogo', '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($key in $PSBoundParameters.Keys) {
        $value = $PSBoundParameters[$key]
        if ($value -is [System.Management.Automation.PSCredential]) {
            Write-Warning "Cannot forward -Credential across the automatic -STA relaunch. Launch PowerShell yourself with -STA, e.g.: powershell.exe -STA -File `"$PSCommandPath`" -Credential (Get-Credential) ..."
            continue
        }
        if ($value -is [switch]) {
            if ($value.IsPresent) { $relaunchArgs += "-$key" }
        }
        else {
            $relaunchArgs += "-$key"
            $relaunchArgs += "`"$value`""
        }
    }
    $hostExePath = (Get-Process -Id $PID).Path
    $proc = Start-Process -FilePath $hostExePath -ArgumentList $relaunchArgs -Wait -PassThru -NoNewWindow
    exit $proc.ExitCode
}

#endregion

#region ================= CONFIGURATION (edit to match your environment) =================

# TCP ports normally associated with each site system role (SMS_SCI_SysResUse.RoleName).
# An empty array means "no inbound port to test" (e.g. internet-facing / outbound-only roles).
$RolePortMap = @{
    'SMS Site Server'                     = @(135, 445)
    'SMS Provider'                        = @(135, 445)
    'SMS Component Server'                = @(135, 445)
    'SMS Distribution Point'              = @(80, 443, 445)
    'SMS Management Point'                = @(80, 443)
    'SMS Software Update Point'           = @(8530, 8531)
    'SMS Fallback Status Point'           = @(80)
    'SMS State Migration Point'           = @(445)
    'SMS Application Web Service'         = @(80, 443)
    'SMS Portal Web Site'                 = @(80, 443)
    'SMS Enrollment Point'                = @(443)
    'SMS Enrollment Server'               = @(443)
    'SMS Certificate Registration Point'  = @(443)
    'SMS Endpoint Protection Point'       = @(443)
    'SMS Reporting Point'                 = @(80, 443)
    'SMS SRS Reporting Point'             = @(80, 443)
    'SMS System Health Validator Point'   = @(443)
    'SMS Multicast Service Point'         = @()
    'SMS Data Warehouse Service Point'    = @(1433)
    'SMS SQL Server'                      = @(1433)
    'SMS Notification Server'             = @(8004, 8005)
    'SMS Service Connection Point'        = @()
    'SMS Site System'                     = @(135, 445)
}

# Windows services normally associated with each role. Adjust service names for named
# SQL instances (e.g. 'MSSQL$INSTANCENAME') or non-default WSUS/reporting setups.
$RoleServiceMap = @{
    'SMS Site Server'                     = @('SMS_EXECUTIVE', 'SMS_SITE_COMPONENT_MANAGER')
    'SMS Provider'                        = @('WinMgmt')
    'SMS Component Server'                = @('SMS_EXECUTIVE')
    'SMS Distribution Point'              = @('W3SVC')
    'SMS Management Point'                = @('W3SVC', 'SMS_EXECUTIVE')
    'SMS Software Update Point'           = @('WsusService', 'W3SVC')
    'SMS Fallback Status Point'           = @('W3SVC')
    'SMS State Migration Point'           = @('SMS_EXECUTIVE')
    'SMS Application Web Service'         = @('W3SVC')
    'SMS Portal Web Site'                 = @('W3SVC')
    'SMS Enrollment Point'                = @('SMS_EXECUTIVE')
    'SMS Enrollment Server'               = @('W3SVC')
    'SMS Certificate Registration Point'  = @('W3SVC')
    'SMS Endpoint Protection Point'       = @('SMS_EXECUTIVE')
    'SMS Reporting Point'                 = @('SMS_EXECUTIVE')
    'SMS SRS Reporting Point'             = @('ReportServer')
    'SMS System Health Validator Point'   = @('W3SVC')
    'SMS Data Warehouse Service Point'    = @('MSSQLSERVER')
    'SMS SQL Server'                      = @('MSSQLSERVER')
    'SMS Notification Server'             = @('SMS_NOTIFICATION_SERVER')
    'SMS Service Connection Point'        = @('SMS_EXECUTIVE')
    'SMS Site System'                     = @('SMS_EXECUTIVE')
}

# Core SCCM Windows services, checked explicitly on the site server(s) in addition to
# the per-role checks above.
$CoreSccmServices = @(
    'SMS_EXECUTIVE',
    'SMS_SITE_COMPONENT_MANAGER',
    'SMS_SITE_VSS_WRITER',
    'SMS_SITE_SQL_BACKUP',
    'SMS_NOTIFICATION_SERVER'
)

#endregion

#region ================= helper functions =================

function New-SccmCimSessionOption {
    param([string]$Protocol)
    if ($Protocol -eq 'Wsman') { New-CimSessionOption -Protocol Wsman }
    else { New-CimSessionOption -Protocol Dcom }
}

function Test-IsLocalComputer {
    # Treat the target as local if its short name matches this machine's computer name.
    # Talking to yourself over a remote CIM/DCOM session can fail with "Access is denied"
    # on Windows Server after the 2023 DCOM hardening update, so local targets always use
    # plain (session-less) WMI calls instead.
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -eq '.' -or $Name -ieq 'localhost' -or $Name -eq '127.0.0.1') { return $true }
    $shortName = ($Name -split '\.')[0]
    return $shortName -ieq $env:COMPUTERNAME
}

function Get-SccmSiteCode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProviderMachineName,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$Protocol = 'Dcom'
    )

    $session = $null
    try {
        $cimParams = @{}
        if (-not (Test-IsLocalComputer -Name $ProviderMachineName)) {
            $sessionParams = @{
                ComputerName  = $ProviderMachineName
                SessionOption = New-SccmCimSessionOption -Protocol $Protocol
            }
            if ($Credential) { $sessionParams['Credential'] = $Credential }
            $session = New-CimSession @sessionParams
            $cimParams = @{ CimSession = $session }
        }

        $locations = Get-CimInstance @cimParams -Namespace 'root\sms' -ClassName 'SMS_ProviderLocation'
        $loc = $locations | Where-Object { $_.ProviderForLocalSite } | Select-Object -First 1
        if (-not $loc) { $loc = $locations | Select-Object -First 1 }
        if (-not $loc) {
            throw "Unable to determine the SCCM site code from '$ProviderMachineName'. Specify -SiteCode explicitly."
        }
        return $loc.SiteCode
    }
    finally {
        if ($session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }
}

function Get-SccmSiteSystemRoles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProviderMachineName,
        [Parameter(Mandatory)][string]$SiteCode,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$Protocol = 'Dcom'
    )

    $session = $null
    try {
        $cimParams = @{}
        if (-not (Test-IsLocalComputer -Name $ProviderMachineName)) {
            $sessionParams = @{
                ComputerName  = $ProviderMachineName
                SessionOption = New-SccmCimSessionOption -Protocol $Protocol
            }
            if ($Credential) { $sessionParams['Credential'] = $Credential }
            $session = New-CimSession @sessionParams
            $cimParams = @{ CimSession = $session }
        }

        $namespace = "root\sms\site_$SiteCode"
        try {
            $rows = Get-CimInstance @cimParams -Namespace $namespace -ClassName 'SMS_SCI_SysResUse'
        }
        catch {
            throw "Failed to query site system roles from '$ProviderMachineName' (namespace '$namespace'). Verify the site code, that the SMS Provider is reachable, and that the account has read access. Underlying error: $($_.Exception.Message)"
        }

        foreach ($row in $rows) {
            $serverName = $row.NetworkOSPath.Trim('\')
            if ([string]::IsNullOrWhiteSpace($serverName)) { continue }
            [pscustomobject]@{
                Server   = $serverName
                RoleName = $row.RoleName
                SiteCode = $row.SiteCode
            }
        }
    }
    finally {
        if ($session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }
}

function Test-TcpPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMs = 1500
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $asyncResult = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $signaled = $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs)
        if (-not $signaled) { return $false }
        try {
            $client.EndConnect($asyncResult)
            return $client.Connected
        }
        catch {
            return $false
        }
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Get-ServiceState {
    # $CimParams is either @{} (query the local machine directly, no session) or
    # @{ CimSession = <session> } (query a remote machine).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$CimParams,
        [Parameter(Mandatory)][string]$ServiceName
    )

    try {
        $svc = Get-CimInstance @CimParams -ClassName 'Win32_Service' -Filter "Name='$ServiceName'" -ErrorAction Stop
        if (-not $svc) {
            return [pscustomobject]@{ Name = $ServiceName; State = 'NotInstalled' }
        }
        return [pscustomobject]@{ Name = $ServiceName; State = $svc.State }
    }
    catch {
        return [pscustomobject]@{ Name = $ServiceName; State = 'QueryFailed' }
    }
}

function Invoke-SccmHealthScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProviderMachineName,
        [Parameter(Mandatory)][string]$SiteCode,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$Protocol = 'Dcom',
        [int]$PortTimeoutMs = 1500
    )

    $siteSystemRoles = @(Get-SccmSiteSystemRoles -ProviderMachineName $ProviderMachineName -SiteCode $SiteCode -Credential $Credential -Protocol $Protocol)
    if (-not $siteSystemRoles -or $siteSystemRoles.Count -eq 0) {
        throw "No site system role data returned from '$ProviderMachineName' for site '$SiteCode'."
    }

    $cimConnCache = @{}

    function Get-CachedCimParams {
        # Returns @{} for the local machine (session-less local WMI), @{ CimSession = <session> }
        # for a remote machine (cached per server for reuse across roles/services), or $null if a
        # remote session could not be established.
        param([string]$Server)
        if ($cimConnCache.ContainsKey($Server)) { return $cimConnCache[$Server] }

        if (Test-IsLocalComputer -Name $Server) {
            $cimConnCache[$Server] = @{}
            return $cimConnCache[$Server]
        }

        $sessionParams = @{
            ComputerName        = $Server
            SessionOption       = New-SccmCimSessionOption -Protocol $Protocol
            OperationTimeoutSec = 15
        }
        if ($Credential) { $sessionParams['Credential'] = $Credential }
        try {
            $session = New-CimSession @sessionParams -ErrorAction Stop
            $cimConnCache[$Server] = @{ CimSession = $session }
        }
        catch {
            $cimConnCache[$Server] = $null
        }
        return $cimConnCache[$Server]
    }

    function New-HealthRow {
        param(
            [string]$Server,
            [string]$Role,
            [bool]$PingOk,
            [int[]]$Ports,
            [string[]]$ServiceNames,
            [datetime]$ScanTime
        )

        $portDetails = New-Object System.Collections.Generic.List[string]
        $anyPortOpen = $false
        $anyPortClosed = $false
        if ($PingOk -and $Ports.Count -gt 0) {
            foreach ($p in $Ports) {
                $open = Test-TcpPort -ComputerName $Server -Port $p -TimeoutMs $PortTimeoutMs
                $portDetails.Add("$p/$(if ($open) { 'Open' } else { 'Closed' })")
                if ($open) { $anyPortOpen = $true } else { $anyPortClosed = $true }
            }
        }

        $svcDetails = New-Object System.Collections.Generic.List[string]
        $anyServiceDown = $false
        $anyServiceUnknown = $false
        if ($PingOk -and $ServiceNames.Count -gt 0) {
            $cimParams = Get-CachedCimParams -Server $Server
            foreach ($svcName in $ServiceNames) {
                if ($cimParams) {
                    $state = Get-ServiceState -CimParams $cimParams -ServiceName $svcName
                    $svcDetails.Add("$svcName=$($state.State)")
                    if ($state.State -eq 'QueryFailed') { $anyServiceUnknown = $true }
                    elseif ($state.State -ne 'Running' -and $state.State -ne 'NotInstalled') { $anyServiceDown = $true }
                }
                else {
                    $svcDetails.Add("$svcName=Unreachable")
                    $anyServiceUnknown = $true
                }
            }
        }

        $severity = 0
        $reasons = New-Object System.Collections.Generic.List[string]
        if (-not $PingOk) {
            $severity = 2
            $reasons.Add('Host did not respond to ping')
        }
        else {
            if ($Ports.Count -gt 0) {
                if ($anyPortClosed -and -not $anyPortOpen) {
                    $severity = [Math]::Max($severity, 2)
                    $reasons.Add('All expected ports closed')
                }
                elseif ($anyPortClosed) {
                    $severity = [Math]::Max($severity, 1)
                    $reasons.Add('One or more expected ports closed')
                }
            }
            if ($ServiceNames.Count -gt 0) {
                if ($anyServiceDown) {
                    $severity = [Math]::Max($severity, 2)
                    $reasons.Add('One or more required services are not running')
                }
                if ($anyServiceUnknown) {
                    $severity = [Math]::Max($severity, 1)
                    $reasons.Add('Could not query one or more services')
                }
            }
        }
        $health = switch ($severity) { 0 { 'Healthy' } 1 { 'Warning' } 2 { 'Critical' } }

        [pscustomobject]@{
            Server   = $Server
            Role     = ($Role -replace '^SMS ', '')
            Ping     = if ($PingOk) { 'Success' } else { 'Failed' }
            Ports    = if ($portDetails.Count) { $portDetails -join ', ' } else { 'N/A' }
            Services = if ($svcDetails.Count) { $svcDetails -join ', ' } else { 'N/A' }
            Health   = $health
            Details  = if ($reasons.Count) { $reasons -join '; ' } else { 'All checks passed' }
            ScanTime = $ScanTime
        }
    }

    $results = New-Object System.Collections.Generic.List[object]
    $scanTime = Get-Date

    foreach ($entry in $siteSystemRoles) {
        Write-Verbose "Scanning $($entry.Server) [$($entry.RoleName)]"
        $pingOk = [bool](Test-Connection -ComputerName $entry.Server -Count 1 -Quiet -ErrorAction SilentlyContinue)

        $ports = $RolePortMap[$entry.RoleName]
        if (-not $ports) { $ports = @() }
        $svcNames = $RoleServiceMap[$entry.RoleName]
        if (-not $svcNames) { $svcNames = @() }

        $results.Add((New-HealthRow -Server $entry.Server -Role $entry.RoleName -PingOk $pingOk -Ports $ports -ServiceNames $svcNames -ScanTime $scanTime))
    }

    $siteServers = @($siteSystemRoles | Where-Object { $_.RoleName -eq 'SMS Site Server' } | Select-Object -ExpandProperty Server -Unique)
    foreach ($server in $siteServers) {
        Write-Verbose "Checking core SCCM services on $server"
        $pingOk = [bool](Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue)
        $results.Add((New-HealthRow -Server $server -Role 'Core SCCM Services' -PingOk $pingOk -Ports @() -ServiceNames $CoreSccmServices -ScanTime $scanTime))
    }

    foreach ($conn in $cimConnCache.Values) {
        if ($conn -and $conn.ContainsKey('CimSession')) {
            Remove-CimSession -CimSession $conn['CimSession'] -ErrorAction SilentlyContinue
        }
    }

    return , ($results.ToArray() | Sort-Object Server, Role)
}

#endregion

#region ================= dashboard =================

function Show-SccmDashboard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [Parameter(Mandatory)][string]$SiteCode,
        [Parameter(Mandatory)][string]$ProviderMachineName,
        [scriptblock]$RescanAction
    )

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $colorHealthy = [System.Drawing.Color]::FromArgb(255, 198, 239, 206)
    $colorWarning = [System.Drawing.Color]::FromArgb(255, 255, 235, 156)
    $colorCritical = [System.Drawing.Color]::FromArgb(255, 255, 199, 206)
    $columns = @('Server', 'Role', 'Ping', 'Ports', 'Services', 'Health', 'Details')

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "SCCM Site System Health Dashboard - Site $SiteCode ($ProviderMachineName)"
    $form.Size = New-Object System.Drawing.Size(1250, 700)
    $form.StartPosition = 'CenterScreen'
    $form.MinimumSize = New-Object System.Drawing.Size(900, 500)

    $topPanel = New-Object System.Windows.Forms.Panel
    $topPanel.Dock = 'Top'
    $topPanel.Height = 70
    $form.Controls.Add($topPanel)

    $lblSummary = New-Object System.Windows.Forms.Label
    $lblSummary.AutoSize = $true
    $lblSummary.Location = New-Object System.Drawing.Point(10, 10)
    $lblSummary.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
    $topPanel.Controls.Add($lblSummary)

    $lblTime = New-Object System.Windows.Forms.Label
    $lblTime.AutoSize = $true
    $lblTime.Location = New-Object System.Drawing.Point(10, 38)
    $lblTime.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $topPanel.Controls.Add($lblTime)

    $lblFilter = New-Object System.Windows.Forms.Label
    $lblFilter.AutoSize = $true
    $lblFilter.Text = 'Filter:'
    $lblFilter.Location = New-Object System.Drawing.Point(870, 18)
    $topPanel.Controls.Add($lblFilter)

    $cmbFilter = New-Object System.Windows.Forms.ComboBox
    $cmbFilter.DropDownStyle = 'DropDownList'
    [void]$cmbFilter.Items.AddRange(@('All', 'Healthy', 'Warning', 'Critical'))
    $cmbFilter.SelectedIndex = 0
    $cmbFilter.Location = New-Object System.Drawing.Point(915, 15)
    $cmbFilter.Width = 110
    $topPanel.Controls.Add($cmbFilter)

    $btnRefresh = New-Object System.Windows.Forms.Button
    $btnRefresh.Text = 'Refresh'
    $btnRefresh.Location = New-Object System.Drawing.Point(1040, 13)
    $btnRefresh.Width = 90
    $btnRefresh.Anchor = 'Top,Right'
    $topPanel.Controls.Add($btnRefresh)

    $btnExport = New-Object System.Windows.Forms.Button
    $btnExport.Text = 'Export CSV'
    $btnExport.Location = New-Object System.Drawing.Point(1040, 42)
    $btnExport.Width = 90
    $btnExport.Anchor = 'Top,Right'
    $topPanel.Controls.Add($btnExport)

    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = 'Fill'
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.AllowUserToResizeRows = $false
    $grid.AutoSizeColumnsMode = 'Fill'
    $grid.SelectionMode = 'FullRowSelect'
    $grid.RowHeadersVisible = $false
    $form.Controls.Add($grid)
    $grid.BringToFront()

    $script:sccmDashCurrentResults = $Results

    function ConvertTo-DashDataTable {
        param($InputObject)
        $table = New-Object System.Data.DataTable
        foreach ($prop in $columns) { [void]$table.Columns.Add($prop, [string]) }
        foreach ($row in $InputObject) {
            $dr = $table.NewRow()
            foreach ($prop in $columns) { $dr[$prop] = [string]$row.$prop }
            [void]$table.Rows.Add($dr)
        }
        return , $table
    }

    function Update-DashGrid {
        param([string]$FilterHealth = 'All')

        $data = if ($FilterHealth -eq 'All') { $script:sccmDashCurrentResults } else { @($script:sccmDashCurrentResults | Where-Object { $_.Health -eq $FilterHealth }) }
        $grid.DataSource = ConvertTo-DashDataTable -InputObject $data

        foreach ($r in $grid.Rows) {
            switch ($r.Cells['Health'].Value) {
                'Healthy' { $r.DefaultCellStyle.BackColor = $colorHealthy }
                'Warning' { $r.DefaultCellStyle.BackColor = $colorWarning }
                'Critical' { $r.DefaultCellStyle.BackColor = $colorCritical }
            }
        }

        $total = $script:sccmDashCurrentResults.Count
        $healthy = @($script:sccmDashCurrentResults | Where-Object { $_.Health -eq 'Healthy' }).Count
        $warning = @($script:sccmDashCurrentResults | Where-Object { $_.Health -eq 'Warning' }).Count
        $critical = @($script:sccmDashCurrentResults | Where-Object { $_.Health -eq 'Critical' }).Count
        $lblSummary.Text = "Checks: $total   |   Healthy: $healthy   Warning: $warning   Critical: $critical"
        $lblSummary.ForeColor = if ($critical -gt 0) { [System.Drawing.Color]::DarkRed } elseif ($warning -gt 0) { [System.Drawing.Color]::DarkGoldenrod } else { [System.Drawing.Color]::DarkGreen }
        $lblTime.Text = "Last scan: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
    }

    Update-DashGrid -FilterHealth 'All'

    $cmbFilter.Add_SelectedIndexChanged({ Update-DashGrid -FilterHealth $cmbFilter.SelectedItem })

    $grid.Add_CellDoubleClick({
            param($eventSender, $e)
            if ($e.RowIndex -lt 0) { return }
            $row = $grid.Rows[$e.RowIndex]
            $msg = "Server:   $($row.Cells['Server'].Value)`r`nRole:     $($row.Cells['Role'].Value)`r`nPing:     $($row.Cells['Ping'].Value)`r`nPorts:    $($row.Cells['Ports'].Value)`r`nServices: $($row.Cells['Services'].Value)`r`nHealth:   $($row.Cells['Health'].Value)`r`nDetails:  $($row.Cells['Details'].Value)"
            [System.Windows.Forms.MessageBox]::Show($msg, 'Site System Detail', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        })

    $btnExport.Add_Click({
            $sfd = New-Object System.Windows.Forms.SaveFileDialog
            $sfd.Filter = 'CSV files (*.csv)|*.csv'
            $sfd.FileName = "SCCM-HealthDashboard-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
            if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $script:sccmDashCurrentResults | Export-Csv -Path $sfd.FileName -NoTypeInformation
                [System.Windows.Forms.MessageBox]::Show("Exported to $($sfd.FileName)", 'Export complete') | Out-Null
            }
        })

    $btnRefresh.Add_Click({
            if (-not $RescanAction) { return }
            $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
            $btnRefresh.Enabled = $false
            try {
                $script:sccmDashCurrentResults = & $RescanAction
                Update-DashGrid -FilterHealth $cmbFilter.SelectedItem
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show("Refresh failed: $($_.Exception.Message)", 'Error', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            }
            finally {
                $btnRefresh.Enabled = $true
                $form.Cursor = [System.Windows.Forms.Cursors]::Default
            }
        })

    [void]$form.ShowDialog()
}

#endregion

#region ================= main =================

if (-not $SiteCode) {
    Write-Host "No -SiteCode specified; auto-detecting from '$ProviderMachineName'..."
    $SiteCode = Get-SccmSiteCode -ProviderMachineName $ProviderMachineName -Credential $Credential -Protocol $Protocol
    Write-Host "Detected site code: $SiteCode"
}

$rescanAction = {
    Invoke-SccmHealthScan -ProviderMachineName $ProviderMachineName -SiteCode $SiteCode -Credential $Credential -Protocol $Protocol -PortTimeoutMs $PortTimeoutMs
}.GetNewClosure()

Write-Host "Scanning site systems and roles for site '$SiteCode' via '$ProviderMachineName'..."
$results = & $rescanAction
Write-Host "Scan complete: $($results.Count) checks performed."

if ($ExportCsvPath) {
    $results | Export-Csv -Path $ExportCsvPath -NoTypeInformation
    Write-Host "Results exported to $ExportCsvPath"
}

if ($NoGui) {
    $results | Format-Table Server, Role, Ping, Ports, Services, Health, Details -AutoSize
}
else {
    try {
        Show-SccmDashboard -Results $results -SiteCode $SiteCode -ProviderMachineName $ProviderMachineName -RescanAction $rescanAction
    }
    catch {
        Write-Warning "Could not display the GUI dashboard ($($_.Exception.Message)); falling back to console output."
        $results | Format-Table Server, Role, Ping, Ports, Services, Health, Details -AutoSize
    }
}

#endregion
