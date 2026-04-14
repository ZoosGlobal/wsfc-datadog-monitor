#Requires -Version 5.1
<#
.SYNOPSIS
    WSFC Health Monitor for Datadog DogStatsD.

.DESCRIPTION
    Collects Windows Server Failover Cluster metrics and sends them to DogStatsD.
    Monitors:
      - Cluster presence / health
      - All cluster node state / health / weight
      - Cluster role/group state / health / owner
      - Cluster resource state / health / owner
      - Cluster Shared Volumes (CSV) state / owner
      - Quorum / witness
      - Networks / interfaces
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
        } catch {}
    }
    return $Default
}

function Sanitize-TagValue {
    param([object]$Value)
    if ($null -eq $Value) { return 'unknown' }
    return ("$Value" -replace '[^a-zA-Z0-9_\-./]', '_').ToLower()
}

function Send-Metric {
    param(
        [Parameter(Mandatory)][string]  $Name,
        [Parameter(Mandatory)][double]  $Value,
        [Parameter()][hashtable]        $Tags = @{}
    )

    $tagSegment = ''
    if ($Tags.Count -gt 0) {
        $tagParts = foreach ($kv in $Tags.GetEnumerator()) {
            $k = Sanitize-TagValue $kv.Key
            $v = Sanitize-TagValue $kv.Value
            "${k}:${v}"
        }
        $tagSegment = '|#' + ($tagParts -join ',')
    }

    $payload = "${Name}:${Value}|g${tagSegment}"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)

    try {
        $Script:UdpClient.Send($bytes, $bytes.Length, $Script:DogStatsDEndpoint) | Out-Null
    }
    catch {
        Write-Warning "[Send-Metric] Failed to send '${Name}': $($_.Exception.Message)"
    }
}

function Initialize-DogStatsDClient {
    param(
        [string] $Hostname,
        [int]    $Port
    )
    $Script:UdpClient = [System.Net.Sockets.UdpClient]::new()
    $Script:DogStatsDEndpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($Hostname), $Port)
}

function Test-Prerequisites {
    $hasModule = [bool](Get-Module -ListAvailable -Name FailoverClusters)
    if (-not $hasModule) {
        Write-Host "[FAIL] FailoverClusters module not found." -ForegroundColor Red
        return $false
    }

    $svc = Get-Service -Name ClusSvc -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Host "[WARN] ClusSvc not found." -ForegroundColor Yellow
    }
    elseif ($svc.Status -ne 'Running') {
        Write-Host "[WARN] ClusSvc is not running (Status: $($svc.Status))." -ForegroundColor Yellow
    }

    return $true
}

function Get-ClusterCimData {
    param([string] $ComputerName = '')

    $cimSession = $null
    $cimArgs = @{}
    try {
        if ($ComputerName -and $ComputerName -ne '') {
            $cimSession = New-CimSession -ComputerName $ComputerName -ErrorAction Stop
            $cimArgs.CimSession = $cimSession
        }

        $cluster = Get-CimInstance -Namespace ROOT\MSCluster -ClassName MSCluster_Cluster @cimArgs |
            Select-Object -First 1 Name, QuorumType, QuorumTypeValue

        if (-not $cluster) { return $null }

        $nodes = @(Get-CimInstance -Namespace ROOT\MSCluster -ClassName MSCluster_Node @cimArgs)
        $groups = @(Get-CimInstance -Namespace ROOT\MSCluster -ClassName MSCluster_ResourceGroup @cimArgs)
        $resources = @(Get-CimInstance -Namespace ROOT\MSCluster -ClassName MSCluster_Resource @cimArgs |
            Select-Object Name, ResourceType, State, OwnerGroup, OwnerNode)

        $clusterIsUp = (@($nodes | Where-Object { $_.State -in @(0,3) }).Count -gt 0)

        $witness = $null
        $qt = "$($cluster.QuorumType)"
        if ($qt -like '*File Share*') {
            $witness = @($resources | Where-Object { $_.ResourceType -like '*File Share Witness*' }) | Select-Object -First 1
        }
        elseif ($qt -like '*Disk*') {
            $witness = @($resources | Where-Object { $_.ResourceType -like '*Physical Disk*' -and ($_.OwnerGroup -like '*Cluster*' -or $_.OwnerGroup -like '*Core*') }) | Select-Object -First 1
        }
        elseif ($qt -like '*Cloud*') {
            $witness = @($resources | Where-Object { $_.ResourceType -like '*Cloud Witness*' }) | Select-Object -First 1
        }
        else {
            $witness = @($resources | Where-Object { $_.ResourceType -like '*Witness*' }) | Select-Object -First 1
        }

        $clusterName = try { [string]$cluster.Name } catch { 'unknown' }
        $quorumType = try { ($cluster.QuorumType -replace '\s+','_').ToLower() } catch { 'unknown' }
        $quorumTypeVal = try { [int]$cluster.QuorumTypeValue } catch { 0 }

        return [pscustomobject]@{
            ClusterName     = $clusterName
            ClusterIsUp     = $clusterIsUp
            QuorumType      = $quorumType
            QuorumTypeValue = $quorumTypeVal
            Witness         = $witness
            Nodes           = $nodes
            Groups          = $groups
            Resources       = $resources
        }
    }
    catch {
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

        $clusterObj = Get-Cluster @clusterArgs -ErrorAction Stop | Select-Object -First 1
        $clusterName = Read-Prop -Obj $clusterObj -Names 'Name' -Default 'unknown-cluster'

        $networks = @(Get-ClusterNetwork @clusterArgs -ErrorAction SilentlyContinue) | ForEach-Object {
            $stateInt = try { [int]$_.State } catch { -1 }
            [pscustomobject]@{
                Name       = try { [string]$_.Name } catch { 'unknown' }
                StateCode  = $stateInt
                StateLabel = if ($NetworkStateMap.ContainsKey($stateInt)) { $NetworkStateMap[$stateInt] } else { 'unknown' }
                Role       = try { ($_.Role).ToString().ToLower() } catch { 'unknown' }
                Metric     = try { [int]$_.Metric } catch { 0 }
            }
        }

        $interfaces = @(Get-ClusterNetworkInterface @clusterArgs -ErrorAction SilentlyContinue) | ForEach-Object {
            $stateInt = try { [int]$_.State } catch { -1 }
            $nodeRaw = try { $_.Node } catch { $null }
            $netRaw  = try { $_.Network } catch { $null }

            [pscustomobject]@{
                Name       = try { [string]$_.Name } catch { 'unknown' }
                Node       = if ($null -eq $nodeRaw) { 'unknown' } elseif ($nodeRaw -is [string]) { $nodeRaw } else { Read-Prop -Obj $nodeRaw -Names 'Name' -Default 'unknown' }
                Network    = if ($null -eq $netRaw) { 'unknown' } elseif ($netRaw -is [string]) { $netRaw } else { Read-Prop -Obj $netRaw -Names 'Name' -Default 'unknown' }
                Adapter    = try { [string]$_.Adapter } catch { 'unknown' }
                StateCode  = $stateInt
                StateLabel = if ($NicStateMap.ContainsKey($stateInt)) { $NicStateMap[$stateInt] } else { 'unknown' }
            }
        }

        return [pscustomobject]@{
            ClusterName = $clusterName
            Networks    = @($networks)
            Interfaces  = @($interfaces)
        }
    }
    catch {
        return $null
    }
}

function Get-ClusterCsvData {
    param([string] $ComputerName = '')

    try {
        Import-Module FailoverClusters -ErrorAction Stop

        $clusterArgs = @{}
        if ($ComputerName -and $ComputerName -ne '') { $clusterArgs.Cluster = $ComputerName }

        $csvs = @(Get-ClusterSharedVolume @clusterArgs -ErrorAction SilentlyContinue)

        $items = foreach ($csv in $csvs) {
            $csvName = try { [string]$csv.Name } catch { 'unknown' }
            $csvState = try { [string]$csv.State } catch { 'unknown' }
            $ownerNode = try { [string]$csv.OwnerNode } catch { 'unknown' }

            $sharedVol = $null
            try { $sharedVol = $csv.SharedVolumeInfo } catch {}
            $path = 'unknown'
            $sizeGB = -1
            $freeGB = -1
            $percentFree = -1

            if ($null -ne $sharedVol) {
                try { $path = [string]$sharedVol.FriendlyVolumeName } catch {}
                try { $part = $sharedVol.Partition; if ($part) { $sizeGB = [math]::Round(($part.Size / 1GB), 2) } } catch {}
                try { $part = $sharedVol.Partition; if ($part) { $freeGB = [math]::Round(($part.FreeSpace / 1GB), 2) } } catch {}
                try { $part = $sharedVol.Partition; if ($part) { $percentFree = [math]::Round($part.PercentFree, 2) } } catch {}
            }

            [pscustomobject]@{
                Name        = $csvName
                State       = $csvState
                OwnerNode   = $ownerNode
                Path        = $path
                SizeGB      = $sizeGB
                FreeGB      = $freeGB
                PercentFree = $percentFree
            }
        }

        return @($items)
    }
    catch {
        return @()
    }
}

function Submit-WSFCMetrics {
    param([string] $ComputerName = '')

    $clusterData = Get-ClusterCimData -ComputerName $ComputerName
    if ($null -eq $clusterData) {
        Send-Metric -Name 'wsfc.cluster.present' -Value 0 -Tags @{ cluster_mode = 'standalone' }
        return
    }

    $cn = Sanitize-TagValue $clusterData.ClusterName
    $clusterTags = @{ cluster_name = $cn; quorum_type = $clusterData.QuorumType }

    Send-Metric -Name 'wsfc.cluster.present' -Value 1 -Tags $clusterTags
    Send-Metric -Name 'wsfc.cluster.health'  -Value ([int][bool]$clusterData.ClusterIsUp) -Tags $clusterTags
    Send-Metric -Name 'wsfc.cluster.state'   -Value ([int][bool]$clusterData.ClusterIsUp) -Tags $clusterTags

    Send-Metric -Name 'wsfc.cluster.nodes.up'     -Value (@($clusterData.Nodes | Where-Object { $_.State -eq 0 }).Count) -Tags $clusterTags
    Send-Metric -Name 'wsfc.cluster.nodes.down'   -Value (@($clusterData.Nodes | Where-Object { $_.State -eq 1 }).Count) -Tags $clusterTags
    Send-Metric -Name 'wsfc.cluster.nodes.paused' -Value (@($clusterData.Nodes | Where-Object { $_.State -eq 2 }).Count) -Tags $clusterTags

    if ($clusterData.Witness) {
        $w = $clusterData.Witness
        $wCode = try { [int]$w.State } catch { -1 }
        $wState = if ($ResStateMap.ContainsKey($wCode)) { $ResStateMap[$wCode] } else { 'unknown' }

        Send-Metric -Name 'wsfc.quorum.witness.health' -Value ([int]($wState -eq 'online')) -Tags @{
            cluster_name       = $cn
            quorum_type        = $clusterData.QuorumType
            quorum_type_value  = [string]$clusterData.QuorumTypeValue
            witness_type       = Sanitize-TagValue $w.ResourceType
            witness_name       = Sanitize-TagValue $w.Name
            witness_state      = $wState
            witness_owner_node = Sanitize-TagValue $w.OwnerNode
        }
    }

    foreach ($node in $clusterData.Nodes) {
        $stateCode = try { [int]$node.State } catch { -1 }
        $stateLabel = if ($NodeStateMap.ContainsKey($stateCode)) { $NodeStateMap[$stateCode] } else { 'unknown' }
        $nodeName   = Sanitize-TagValue $node.Name
        $nodeWeight  = try { [int]$node.NodeWeight } catch { -1 }

        $nodeTags = @{
            cluster_name = $cn
            node_name    = $nodeName
            node_state   = $stateLabel
        }

        Send-Metric -Name 'wsfc.node.health' -Value ([int]($stateCode -eq 0)) -Tags $nodeTags
        Send-Metric -Name 'wsfc.node.state'  -Value $stateCode -Tags $nodeTags
        Send-Metric -Name 'wsfc.node.weight'  -Value $nodeWeight -Tags $nodeTags
    }

    foreach ($group in $clusterData.Groups) {
        $groupName = Sanitize-TagValue $group.Name
        $ownerNode = Sanitize-TagValue (Read-Prop -Obj $group -Names 'OwnerNode' -Default 'unknown')
        $groupStateCode = try { [int]$group.State } catch { -1 }
        $groupStateLabel = if ($ResStateMap.ContainsKey($groupStateCode)) { $ResStateMap[$groupStateCode] } else { 'unknown' }

        $groupTags = @{
            cluster_name = $cn
            role_name    = $groupName
            owner_node   = $ownerNode
            role_state   = $groupStateLabel
        }

        Send-Metric -Name 'wsfc.role.health' -Value ([int]($groupStateCode -eq 3)) -Tags $groupTags
        Send-Metric -Name 'wsfc.role.state'  -Value $groupStateCode -Tags $groupTags
    }

    foreach ($res in $clusterData.Resources) {
        $resName = Sanitize-TagValue $res.Name
        $ownerGroup = Sanitize-TagValue (Read-Prop -Obj $res -Names 'OwnerGroup' -Default 'unknown')
        $ownerNode  = Sanitize-TagValue (Read-Prop -Obj $res -Names 'OwnerNode' -Default 'unknown')
        $resType    = Sanitize-TagValue (Read-Prop -Obj $res -Names 'ResourceType' -Default 'unknown')
        $resStateCode = try { [int]$res.State } catch { -1 }
        $resStateLabel = if ($ResStateMap.ContainsKey($resStateCode)) { $ResStateMap[$resStateCode] } else { 'unknown' }

        $resTags = @{
            cluster_name   = $cn
            resource_name  = $resName
            resource_type  = $resType
            owner_group    = $ownerGroup
            owner_node     = $ownerNode
            resource_state = $resStateLabel
        }

        Send-Metric -Name 'wsfc.resource.health' -Value ([int]($resStateCode -eq 3)) -Tags $resTags
        Send-Metric -Name 'wsfc.resource.state'  -Value $resStateCode -Tags $resTags
    }

    foreach ($csv in (Get-ClusterCsvData -ComputerName $ComputerName)) {
        $csvName = Sanitize-TagValue $csv.Name
        $csvOwner = Sanitize-TagValue $csv.OwnerNode
        $csvState = Sanitize-TagValue $csv.State

        $csvTags = @{
            cluster_name = $cn
            csv_name     = $csvName
            owner_node   = $csvOwner
            csv_state    = $csvState
        }

        Send-Metric -Name 'wsfc.csv.health'      -Value ([int]($csv.State -eq 'Online')) -Tags $csvTags
        Send-Metric -Name 'wsfc.csv.state'       -Value ([int]([string]::IsNullOrWhiteSpace($csv.State) ? -1 : 0)) -Tags $csvTags
        Send-Metric -Name 'wsfc.csv.free_gb'     -Value ([double]$csv.FreeGB) -Tags $csvTags
        Send-Metric -Name 'wsfc.csv.size_gb'     -Value ([double]$csv.SizeGB) -Tags $csvTags
        Send-Metric -Name 'wsfc.csv.percent_free' -Value ([double]$csv.PercentFree) -Tags $csvTags
    }

    $netData = Get-ClusterNetworkData -ComputerName $ComputerName
    if ($null -ne $netData) {
        $cn2 = Sanitize-TagValue $netData.ClusterName

        foreach ($net in $netData.Networks) {
            $netName = Sanitize-TagValue $net.Name
            $netTags = @{ cluster_name = $cn2; network_name = $netName; network_role = $net.Role; network_state = $net.StateLabel }
            Send-Metric -Name 'wsfc.network.health' -Value ([int]($net.StateCode -eq 2)) -Tags $netTags
            Send-Metric -Name 'wsfc.network.state'  -Value $net.StateCode -Tags $netTags
            Send-Metric -Name 'wsfc.network.metric'  -Value $net.Metric -Tags $netTags
        }

        foreach ($nic in $netData.Interfaces) {
            $nicTags = @{
                cluster_name    = $cn2
                node_name       = Sanitize-TagValue $nic.Node
                network_name    = Sanitize-TagValue $nic.Network
                adapter_name    = Sanitize-TagValue $nic.Adapter
                interface_name  = Sanitize-TagValue $nic.Name
                interface_state = $nic.StateLabel
            }
            Send-Metric -Name 'wsfc.network_interface.health' -Value ([int]($nic.StateCode -eq 4)) -Tags $nicTags
            Send-Metric -Name 'wsfc.network_interface.state'  -Value $nic.StateCode -Tags $nicTags
        }
    }
}

function Get-ClusterNetworkData {
    param([string] $ComputerName = '')

    try {
        Import-Module FailoverClusters -ErrorAction Stop
        $clusterArgs = @{}
        if ($ComputerName -and $ComputerName -ne '') { $clusterArgs.Cluster = $ComputerName }

        $clusterObj = Get-Cluster @clusterArgs -ErrorAction Stop | Select-Object -First 1
        $clusterName = Read-Prop -Obj $clusterObj -Names 'Name' -Default 'unknown-cluster'

        $networks = @(Get-ClusterNetwork @clusterArgs -ErrorAction SilentlyContinue) | ForEach-Object {
            $stateInt = try { [int]$_.State } catch { -1 }
            [pscustomobject]@{
                Name       = try { [string]$_.Name } catch { 'unknown' }
                StateCode  = $stateInt
                StateLabel = if ($NetworkStateMap.ContainsKey($stateInt)) { $NetworkStateMap[$stateInt] } else { 'unknown' }
                Role       = try { ($_.Role).ToString().ToLower() } catch { 'unknown' }
                Metric     = try { [int]$_.Metric } catch { 0 }
            }
        }

        $interfaces = @(Get-ClusterNetworkInterface @clusterArgs -ErrorAction SilentlyContinue) | ForEach-Object {
            $stateInt = try { [int]$_.State } catch { -1 }
            $nodeRaw = try { $_.Node } catch { $null }
            $netRaw  = try { $_.Network } catch { $null }

            [pscustomobject]@{
                Name       = try { [string]$_.Name } catch { 'unknown' }
                Node       = if ($null -eq $nodeRaw) { 'unknown' } elseif ($nodeRaw -is [string]) { $nodeRaw } else { Read-Prop -Obj $nodeRaw -Names 'Name' -Default 'unknown' }
                Network    = if ($null -eq $netRaw) { 'unknown' } elseif ($netRaw -is [string]) { $netRaw } else { Read-Prop -Obj $netRaw -Names 'Name' -Default 'unknown' }
                Adapter    = try { [string]$_.Adapter } catch { 'unknown' }
                StateCode  = $stateInt
                StateLabel = if ($NicStateMap.ContainsKey($stateInt)) { $NicStateMap[$stateInt] } else { 'unknown' }
            }
        }

        return [pscustomobject]@{
            ClusterName = $clusterName
            Networks    = @($networks)
            Interfaces  = @($interfaces)
        }
    }
    catch {
        return $null
    }
}

if (-not (Test-Prerequisites)) { exit 1 }

Initialize-DogStatsDClient -Hostname $DogStatsDHost -Port $DogStatsDPort

try {
    if ($RunOnce) {
        Submit-WSFCMetrics -ComputerName $ComputerName
    }
    else {
        while ($true) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            Submit-WSFCMetrics -ComputerName $ComputerName
            $sw.Stop()
            $sleepMs = [Math]::Max(0, 60000 - $sw.ElapsedMilliseconds)
            Start-Sleep -Milliseconds $sleepMs
        }
    }
}
finally {
    if ($Script:UdpClient) {
        $Script:UdpClient.Close()
        $Script:UdpClient.Dispose()
    }
}