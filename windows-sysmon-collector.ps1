<#
Case Memory Windows Sysmon collector — LAB USE ONLY
Requires: Windows PowerShell 5.1+, Sysmon installed and logging to Microsoft-Windows-Sysmon/Operational.
Configure $IngestUrl and $IngestToken. Keep the token private. This sends selected Sysmon event metadata to your deployed Case Memory endpoint.
Start in a dedicated lab VM. Do not forward production/regulated logs without authorization and data-minimization review.
#>
$IngestUrl = "https://YOUR-PROJECT.vercel.app/api/ingest"
$IngestToken = "PASTE_COLLECTOR_INGEST_TOKEN_HERE"
$LogName = "Microsoft-Windows-Sysmon/Operational"
$PollSeconds = 3
$StatePath = Join-Path $env:LOCALAPPDATA "CaseMemory-sysmon-recordid.txt"
if ($IngestUrl -match "YOUR-PROJECT" -or $IngestToken -match "PASTE_") { throw "Edit IngestUrl and IngestToken in this script first." }
$last = 0
if (Test-Path $StatePath) { try { $last = [long](Get-Content $StatePath -Raw) } catch {} }
Write-Host "Case Memory Sysmon collector started. Log=$LogName LastRecordId=$last. Ctrl+C to stop."
while ($true) {
  try {
    $events = Get-WinEvent -FilterHashtable @{LogName=$LogName} -MaxEvents 100 -ErrorAction Stop | Where-Object { $_.RecordId -gt $last } | Sort-Object RecordId
    foreach ($ev in $events) {
      [xml]$xml = $ev.ToXml()
      $fields = @{}
      foreach ($d in $xml.Event.EventData.Data) { if ($d.Name) { $fields[[string]$d.Name] = [string]$d.'#text' } }
      $computer = [string]$xml.Event.System.Computer
      $user = [string]$fields['User']
      if (-not $user) { $user = [string]$xml.Event.System.Security.UserID }
      $payload = @{
        event_id = "$computer-Sysmon-$($ev.RecordId)"
        source = "Sysmon"
        event_id_numeric = [int]$ev.Id
        event_type = switch ([int]$ev.Id) { 1 {"ProcessCreate"} 3 {"NetworkConnect"} 7 {"ImageLoaded"} 10 {"ProcessAccess"} 11 {"FileCreate"} 12 {"RegistryEvent"} 13 {"RegistryValueSet"} 22 {"DNSQuery"} default {"SysmonEvent$($ev.Id)"} }
        timestamp = $ev.TimeCreated.ToUniversalTime().ToString("o")
        host = $computer
        user = $user
        record_id = [long]$ev.RecordId
        detail = ($fields | ConvertTo-Json -Compress -Depth 4)
        fields = $fields
      } | ConvertTo-Json -Depth 6
      try {
        Invoke-RestMethod -Method Post -Uri $IngestUrl -Headers @{Authorization="Bearer $IngestToken"} -ContentType "application/json" -Body $payload -TimeoutSec 10 | Out-Null
        $last = [long]$ev.RecordId
        Set-Content -Path $StatePath -Value $last -NoNewline
        Write-Host ("Sent Sysmon Event ID {0}, Record {1}, {2}" -f $ev.Id,$ev.RecordId,$computer)
      } catch { Write-Warning ("Ingest failed for record {0}: {1}" -f $ev.RecordId,$_.Exception.Message); break }
    }
  } catch { if ($_.Exception.Message -notmatch "No events were found") { Write-Warning $_.Exception.Message } }
  Start-Sleep -Seconds $PollSeconds
}
