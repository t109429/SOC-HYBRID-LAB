<#
Exports *real* Windows event-log records into the project's normalized JSONL schema.
Run on Windows PowerShell 5.1+; administrator privileges may be required.
This script reads local logs only, executes no suspicious code and contacts no servers.
NEVER commit real log exports without explicit authorization and sanitization.
#>
[CmdletBinding()]
param(
    [int]$HoursBack = 24,
    [int]$MaxEventsPerLog = 2000,
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\.local\live_windows_events.jsonl')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$since = (Get-Date).AddHours(-$HoursBack)
$all = New-Object System.Collections.Generic.List[object]
$filters = @(
    @{ LogName = 'Security'; Id = @(4624,4625,4688,4698); StartTime = $since },
    @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = @(1,3); StartTime = $since }
)
foreach ($filter in $filters) {
    try {
        $found = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEventsPerLog -ErrorAction Stop)
    } catch {
        Write-Warning "Log unavailable or no matching events ($($filter.LogName)): $($_.Exception.Message)"
        continue
    }
    foreach ($event in $found) {
        [xml]$xml = $event.ToXml()
        $fields = @{}
        foreach ($entry in @($xml.Event.EventData.Data)) {
            if ($null -ne $entry -and $entry.Name) { $fields[[string]$entry.Name] = [string]$entry.'#text' }
        }
        $eid = [int]$event.Id
        $user = ''
        $domain = ''
        if ($eid -in @(4624,4625)) {
            $user = [string]$fields['TargetUserName']
            $domain = [string]$fields['TargetDomainName']
        } elseif ($eid -eq 4688 -and $fields['TargetUserName']) {
            $user = [string]$fields['TargetUserName']
            $domain = [string]$fields['TargetDomainName']
        } elseif ($eid -in @(4688,4698)) {
            $user = [string]$fields['SubjectUserName']
            $domain = [string]$fields['SubjectDomainName']
        } else {
            $user = [string]$fields['User']
        }
        $image = ''
        if ($eid -eq 4688) { $image = [string]$fields['NewProcessName'] }
        elseif ($eid -in @(1,3)) { $image = [string]$fields['Image'] }
        $obj = [ordered]@{
            timestamp = $event.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            event_id = $eid
            channel = [string]$event.LogName
            record_id = [long]$event.RecordId
            host = [string]$event.MachineName
            user = $user
            user_domain = $domain
            source_ip = if ($eid -in @(4624,4625)) { [string]$fields['IpAddress'] } else { '' }
            logon_type = if ($eid -in @(4624,4625)) { [string]$fields['LogonType'] } else { '' }
            image = $image
            command_line = if ($eid -eq 4688) { [string]$fields['CommandLine'] } elseif ($eid -eq 1) { [string]$fields['CommandLine'] } else { '' }
            process_guid = [string]$fields['ProcessGuid']
            destination_ip = [string]$fields['DestinationIp']
            initiated = [string]$fields['Initiated']
            destination_port = [string]$fields['DestinationPort']
            task_name = [string]$fields['TaskName']
            task_content = [string]$fields['TaskContent']
        }
        $all.Add([pscustomobject]$obj)
    }
}
$folder = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
if ($all.Count -eq 0) {
    Set-Content -LiteralPath $OutputPath -Value '' -Encoding utf8
} else {
    $all | Sort-Object timestamp | ForEach-Object { ConvertTo-Json -InputObject $_ -Compress -Depth 5 } | Set-Content -LiteralPath $OutputPath -Encoding utf8
}
Write-Host "Exported $($all.Count) normalized events to $OutputPath"
Write-Warning 'PRIVATE DATA: This file may include usernames, IPs, commands, and potentially secrets. Do not upload it to GitHub.'
