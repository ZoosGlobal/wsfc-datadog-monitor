#Requires -Version 5.1
<#
.SYNOPSIS
    WSFC Health Monitor - Collects Windows Server Failover Cluster health metrics
    and submits them as gauges to the Datadog DogStatsD listener every 60 seconds.

.DESCRIPTION
    Monitors:
      * Cluster overall health           -> wsfc.cluster.health
      * Cluster node health              -> wsfc.node.health / wsfc.node.state
      * Quorum type, state, witness      -> wsfc.quorum.witness.health (+ tags)
      * Cluster network health           -> wsfc.network.health / wsfc.network.state
      * Cluster network interface health -> wsfc.network_interface.health / wsfc.network_interface.state
#>

[CmdletBinding()]
param(
    [string] $DogStatsDHost = '127.0.0.1',
    [int]    $DogStatsDPort = 8125,
    [string] $ComputerName  = '',
    [switch] $RunOnce
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function Test-Prerequisites {
    $pass = $true
    Write-Host "`n[Pre-Flight] Checking prerequisites..." -ForegroundColor Cyan

    try {
        $null = Get-CimInstance -Namespace ROOT\MSCluster -ClassName MSCluster_Cluster -ErrorAction Stop | Select-Object -First 1
        Write-Host "  [OK] ROOT\MSCluster WMI namespace is available." -ForegroundColor Green
    }
    catch {
        Write-Host "  [FAIL] ROOT\MSCluster WMI namespace not found." -ForegroundColor Red
        Write-Host "         Fix: Install-WindowsFeature -Name Failover-Clustering -IncludeManagementTools" -ForegroundColor Yellow
        $pass = $false
    }

    if (Get-Module -ListAvailable -Name FailoverClusters) {
        Write-Host "  [OK] FailoverClusters PowerShell module is available." -ForegroundColor Green
    }
    else {
        Write-Host "  [FAIL] FailoverClusters PowerShell module not found." -ForegroundColor Red
        Write-Host "         Fix: Install-WindowsFeature -Name RSAT-Clustering-PowerShell" -ForegroundColor Yellow
        $pass = $false
    }

    $svc = Get-Service -Name ClusSvc -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Host "  [FAIL] Cluster Service (ClusSvc) not found - node may not be a cluster member." -ForegroundColor Red
        $pass = $false
    }
    elseif ($svc.Status -ne 'Running') {
        Write-Host "  [WARN] Cluster Service (ClusSvc) is NOT running (Status: $($svc.Status))." -ForegroundColor Yellow
        Write-Host "         Fix: Start-Service ClusSvc" -ForegroundColor White
        $pass = $false
    }
    else {
        Write-Host "  [OK] Cluster Service (ClusSvc) is running." -ForegroundColor Green
    }

    Write-Host ""
    return $pass
}

function Initialize-DogStatsDClient {
    param(
        [string] $Hostname,
        [int]    $Port
    )
    $Script:UdpClient         = [System.Net.Sockets.UdpClient]::new()
    $Script:DogStatsDEndpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($Hostname), $Port)
    Write-Host "[WSFC Monitor] DogStatsD target: ${Hostname}:${Port}" -ForegroundColor Cyan
}

function Send-Metric {
    param(
        [Parameter(Mandatory)][string]    $Name,
        [Parameter(Mandatory)][double]    $Value,
        [Parameter()]        [hashtable] $Tags = @{}
    )

    $tagSegment = ''
    if ($Tags.Count -gt 0) {
        $tagParts = foreach ($kv in $Tags.GetEnumerator()) {
            $k = ($kv.Key   -replace '[^a-zA-Z0-9_\-./]', '_').ToLower()
            $v = ($kv.Value -replace '[^a-zA-Z0-9_\-./]', '_').ToLower()
            "${k}:${v}"
        }
        $tagSegment = '|#' + ($tagParts -join ',')
    }

    $payload = "${Name}:${Value}|g${tagSegment}"
    $bytes   = [System.Text.Encoding]::UTF8.GetBytes($payload)

    try {
        $Script:UdpClient.Send($bytes, $bytes.Length, $Script:DogStatsDEndpoint) | Out-Null
        Write-Verbose "  >> $payload"
    }
    catch {
        Write-Warning "[Send-Metric] Failed to send '${Name}': $($_.Exception.Message)"
    }
}

$NodeStateMap    = @{ 0='up'; 1='down'; 2='paused'; 3='joining' }
$ResStateMap     = @{ 0='unknown'; 1='inherited'; 2='initializing'; 3='online'; 4='offline'; 128='failed'; 129='pending'; 130='offline_pending'; 131='online_pending' }
$NetworkStateMap = @{ 0='down'; 1='partially_up'; 2='up'; 3='unreachable' }
$NicStateMap     = @{ 0='unknown'; 1='unavailable'; 2='failed'; 3='unreachable'; 4='up' }

function Read-Prop {
    param(
        [object]   $Obj,
        [string[]] $Names,
        [string]   $Default = 'unknown'
    )
    foreach ($n in $Names) {
        try {
            $v = $Obj.$n
            if ($null -ne $v -and "$v" -ne '') { return "$v" }
        }
        catch { }
    }
    return $Default
}

function Get-ClusterCimData {
    param([string] $ComputerName = '')

    $cimSession = $null
    $cimArgs    = @{}

    try {
        if ($ComputerName -and $ComputerName -ne '') {
            $cimSession         = New-CimSession -ComputerName $ComputerName -ErrorAction Stop
            $cimArgs.CimSession = $cimSession
        }

        $cluster = Get-CimInstance -Namespace ROOT\MSCluster -ClassName MSCluster_Cluster @cimArgs |
                   Select-Object -First 1 Name, QuorumType, QuorumTypeValue

        if (-not $cluster) {
            Write-Warning '[Get-ClusterCimData] No cluster found on this node.'
            return $null
        }

        $nodes     = @(Get-CimInstance -Namespace ROOT\MSCluster -ClassName MSCluster_Node          @cimArgs)
        $groups    = @(Get-CimInstance -Namespace ROOT\MSCluster -ClassName MSCluster_ResourceGroup @cimArgs)
        $resources = @(Get-CimInstance -Namespace ROOT\MSCluster -ClassName MSCluster_Resource      @cimArgs |
                       Select-Object Name, ResourceType, State, OwnerGroup, OwnerNode)

        $clusterIsUp = (@($nodes | Where-Object { $_.State -in @(0, 3) }).Count -gt 0)

        $witness = $null
        $qt = "$($cluster.QuorumType)"
        if     ($qt -like '*File Share*') { $witness = @($resources | Where-Object { $_.ResourceType -like '*File Share Witness*' }) | Select-Object -First 1 }
        elseif ($qt -like '*Disk*')       { $witness = @($resources | Where-Object { $_.ResourceType -like '*Physical Disk*' -and ($_.OwnerGroup -like '*Cluster*' -or $_.OwnerGroup -like '*Core*') }) | Select-Object -First 1 }
        elseif ($qt -like '*Cloud*')      { $witness = @($resources | Where-Object { $_.ResourceType -like '*Cloud Witness*' }) | Select-Object -First 1 }
        else                              { $witness = @($resources | Where-Object { $_.ResourceType -like '*Witness*' }) | Select-Object -First 1 }

        $wState = 'none'; $wType = 'none'; $wName = 'none'; $wOwner = 'none'
        if ($null -ne $witness) {
            $wCode  = try { [int]$witness.State } catch { -1 }
            $wState = if ($ResStateMap.ContainsKey($wCode)) { $ResStateMap[$wCode] } else { 'unknown' }
            $wType  = try { ($witness.ResourceType -replace '\s+','_').ToLower() } catch { 'unknown' }
            $wName  = try { $witness.Name -replace '[^a-zA-Z0-9_\-]','_' } catch { 'unknown' }
            $wOwner = try { if ($witness.OwnerNode) { ($witness.OwnerNode -replace '[^a-zA-Z0-9_\-]','_').ToLower() } else { 'none' } } catch { 'none' }
        }

        $coreGroup = $null
        try { $coreGroup = @($groups | Where-Object { $_.IsCoreGroup -eq $true }) | Select-Object -First 1 } catch { Write-Verbose '[Get-ClusterCimData] IsCoreGroup not available, trying GroupType.' }
        if ($null -eq $coreGroup) {
            try { $coreGroup = @($groups | Where-Object { [int]$_.GroupType -eq 1 }) | Select-Object -First 1 } catch { Write-Verbose '[Get-ClusterCimData] GroupType not available, using name fallback.' }
        }
        if ($null -eq $coreGroup) {
            $coreGroup = @($groups | Where-Object { $_.Name -like '*Cluster Group*' -or $_.Name -like '*Core*' }) | Select-Object -First 1
        }

        $coreGroupState = 'not_found'
        if ($null -ne $coreGroup) {
            $cgCode         = try { [int]$coreGroup.State } catch { -1 }
            $coreGroupState = if ($ResStateMap.ContainsKey($cgCode)) { $ResStateMap[$cgCode] } else { 'unknown' }
        }

        $clusterName   = try { [string]$cluster.Name } catch { 'unknown' }
        $quorumType    = try { ($cluster.QuorumType -replace '\s+','_').ToLower() } catch { 'unknown' }
        $quorumTypeVal = try { [int]$cluster.QuorumTypeValue } catch { 0 }
        $nodesUp       = @($nodes | Where-Object { $_.State -eq 0 }).Count
        $nodesDown     = @($nodes | Where-Object { $_.State -eq 1 }).Count
        $nodesPaused   = @($nodes | Where-Object { $_.State -eq 2 }).Count

        return [pscustomobject]@{
            ClusterName     = $clusterName
            ClusterIsUp     = $clusterIsUp
            QuorumType      = $quorumType
            QuorumTypeValue = $quorumTypeVal
            WitnessState    = $wState
            WitnessType     = $wType
            WitnessName     = $wName
            WitnessOwner    = $wOwner
            CoreGroupState  = $coreGroupState
            NodesUp         = $nodesUp
            NodesDown       = $nodesDown
            NodesPaused     = $nodesPaused
            Nodes           = $nodes
        }
    }
    catch {
        Write-Warning "[Get-ClusterCimData] $($_.Exception.Message)"
        return $null
    }
    finally {
        if ($cimSession) { $cimSession | Remove-CimSession -ErrorAction SilentlyContinue }
    }
}

function Get-ClusterNetworkData {
    param([string] $ComputerName = '')

    try {
        Import-Module FailoverClusters -ErrorAction Stop

        $clusterArgs = @{}
        if ($ComputerName -and $ComputerName -ne '') { $clusterArgs.Cluster = $ComputerName }

        $clusterObj  = Get-Cluster @clusterArgs -ErrorAction Stop | Select-Object -First 1
        $clusterName = Read-Prop -Obj $clusterObj -Names 'Name' -Default 'unknown-cluster'

        $networks = @(Get-ClusterNetwork @clusterArgs -ErrorAction SilentlyContinue) |
                    ForEach-Object {
                        $netName    = try { [string]$_.Name }  catch { 'unknown' }
                        $stateInt   = try { [int]$_.State }    catch { -1 }
                        $stateLabel = if ($NetworkStateMap.ContainsKey($stateInt)) { $NetworkStateMap[$stateInt] } else { 'unknown' }
                        $role       = try { ($_.Role).ToString().ToLower() } catch { 'unknown' }
                        $metric     = try { [int]$_.Metric }   catch { 0 }
                        [pscustomobject]@{ Name = $netName; StateCode = $stateInt; StateLabel = $stateLabel; Role = $role; Metric = $metric }
                    }

        $interfaces = @(Get-ClusterNetworkInterface @clusterArgs -ErrorAction SilentlyContinue) |
                      ForEach-Object {
                          $ifName     = try { [string]$_.Name }    catch { 'unknown' }
                          $stateInt   = try { [int]$_.State }      catch { -1 }
                          $stateLabel = if ($NicStateMap.ContainsKey($stateInt)) { $NicStateMap[$stateInt] } else { 'unknown' }
                          $adapter    = try { [string]$_.Adapter } catch { 'unknown' }
                          $nodeRaw    = try { $_.Node }    catch { $null }
                          $nodeName   = if ($null -eq $nodeRaw) { 'unknown' } elseif ($nodeRaw -is [string]) { $nodeRaw } else { Read-Prop -Obj $nodeRaw -Names 'Name' -Default 'unknown' }
                          $netRaw     = try { $_.Network } catch { $null }
                          $netName    = if ($null -eq $netRaw) { 'unknown' } elseif ($netRaw -is [string]) { $netRaw } else { Read-Prop -Obj $netRaw -Names 'Name' -Default 'unknown' }
                          [pscustomobject]@{ Name = $ifName; Node = $nodeName; Network = $netName; Adapter = $adapter; StateCode = $stateInt; StateLabel = $stateLabel }
                      }

        return [pscustomobject]@{
            ClusterName = $clusterName
            Networks    = @($networks)
            Interfaces  = @($interfaces)
        }
    }
    catch {
        Write-Warning "[Get-ClusterNetworkData] $($_.Exception.Message)"
        return $null
    }
}

function Submit-WSFCMetrics {
    param([string] $ComputerName = '')

    Write-Host "[$([datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))] Collecting WSFC metrics..." -ForegroundColor DarkCyan

    $clusterData = Get-ClusterCimData -ComputerName $ComputerName
    if ($null -ne $clusterData) {
        $cn = ($clusterData.ClusterName -replace '[^a-zA-Z0-9_\-]','_').ToLower()
        $clusterTags = @{ cluster_name = $cn; quorum_type = $clusterData.QuorumType; core_group_state = $clusterData.CoreGroupState }

        Send-Metric -Name 'wsfc.cluster.health'       -Value ([int][bool]$clusterData.ClusterIsUp) -Tags $clusterTags
        Send-Metric -Name 'wsfc.cluster.nodes.up'     -Value $clusterData.NodesUp                 -Tags $clusterTags
        Send-Metric -Name 'wsfc.cluster.nodes.down'   -Value $clusterData.NodesDown               -Tags $clusterTags
        Send-Metric -Name 'wsfc.cluster.nodes.paused' -Value $clusterData.NodesPaused             -Tags $clusterTags

        $witnessHealth = if ($clusterData.WitnessState -eq 'online') { 1 } else { 0 }
        Send-Metric -Name 'wsfc.quorum.witness.health' -Value $witnessHealth -Tags @{
            cluster_name       = $cn
            quorum_type        = $clusterData.QuorumType
            quorum_type_value  = [string]$clusterData.QuorumTypeValue
            witness_type       = $clusterData.WitnessType
            witness_name       = $clusterData.WitnessName
            witness_state      = $clusterData.WitnessState
            witness_owner_node = $clusterData.WitnessOwner
        }

        foreach ($node in $clusterData.Nodes) {
            $stateCode  = try { [int]$node.State } catch { -1 }
            $stateLabel = if ($NodeStateMap.ContainsKey($stateCode)) { $NodeStateMap[$stateCode] } else { 'unknown' }
            $nodeName   = ($node.Name -replace '[^a-zA-Z0-9_\-]','_').ToLower()
            $nodeTags   = @{ cluster_name = $cn; node_name = $nodeName; node_state = $stateLabel }
            Send-Metric -Name 'wsfc.node.health' -Value ([int]($stateCode -eq 0)) -Tags $nodeTags
            Send-Metric -Name 'wsfc.node.state'  -Value $stateCode                -Tags $nodeTags
        }
    }

    $netData = Get-ClusterNetworkData -ComputerName $ComputerName
    if ($null -ne $netData) {
        $cn = ($netData.ClusterName -replace '[^a-zA-Z0-9_\-]','_').ToLower()

        foreach ($net in $netData.Networks) {
            $netName = ($net.Name -replace '[^a-zA-Z0-9_\-]','_').ToLower()
            $netTags = @{ cluster_name = $cn; network_name = $netName; network_role = $net.Role; network_state = $net.StateLabel }
            Send-Metric -Name 'wsfc.network.health' -Value ([int]($net.StateCode -eq 2)) -Tags $netTags
            Send-Metric -Name 'wsfc.network.state'  -Value $net.StateCode               -Tags $netTags
            Send-Metric -Name 'wsfc.network.metric' -Value $net.Metric                  -Tags $netTags
        }

        foreach ($nic in $netData.Interfaces) {
            $nicName   = ($nic.Name    -replace '[^a-zA-Z0-9_\-]','_').ToLower()
            $nodeName  = ($nic.Node    -replace '[^a-zA-Z0-9_\-]','_').ToLower()
            $netName   = ($nic.Network -replace '[^a-zA-Z0-9_\-]','_').ToLower()
            $adptrName = ($nic.Adapter -replace '[^a-zA-Z0-9_\-]','_').ToLower()
            $nicTags   = @{ cluster_name = $cn; node_name = $nodeName; network_name = $netName; adapter_name = $adptrName; interface_name = $nicName; interface_state = $nic.StateLabel }
            Send-Metric -Name 'wsfc.network_interface.health' -Value ([int]($nic.StateCode -eq 4)) -Tags $nicTags
            Send-Metric -Name 'wsfc.network_interface.state'  -Value $nic.StateCode               -Tags $nicTags
        }
    }

    Write-Host "[$([datetime]::Now.ToString('HH:mm:ss'))] Metrics submitted." -ForegroundColor Green
}

if (-not (Test-Prerequisites)) {
    Write-Host "[WSFC Monitor] Prerequisites not met. Please fix the issues above and re-run." -ForegroundColor Red
    exit 1
}

Initialize-DogStatsDClient -Hostname $DogStatsDHost -Port $DogStatsDPort

try {
    if ($RunOnce) {
        Submit-WSFCMetrics -ComputerName $ComputerName
        Write-Host '[WSFC Monitor] Single collection cycle complete.' -ForegroundColor Green
    }
    else {
        Write-Host '[WSFC Monitor] Running every 60 seconds. Press Ctrl+C to stop.' -ForegroundColor Cyan
        while ($true) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            Submit-WSFCMetrics -ComputerName $ComputerName
            $sw.Stop()
            $sleepMs = [Math]::Max(0, 60000 - $sw.ElapsedMilliseconds)
            Write-Verbose "[Scheduler] Collection: $($sw.ElapsedMilliseconds)ms. Sleeping: $([Math]::Round($sleepMs/1000,1))s."
            Start-Sleep -Milliseconds $sleepMs
        }
    }
}
finally {
    $Script:UdpClient.Close()
    $Script:UdpClient.Dispose()
    Write-Host '[WSFC Monitor] Stopped. UDP client closed.' -ForegroundColor Yellow
}