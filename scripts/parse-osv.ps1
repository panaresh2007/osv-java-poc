param(
    [string]$JsonFile,
    [string]$CsvFile,
    [string]$ScanType = "Direct"
)

$json = Get-Content $JsonFile | ConvertFrom-Json
$rows = @()

$json.results | ForEach-Object {
    $_.packages | ForEach-Object {
        $pkg = $_.package
        $_.vulnerabilities | ForEach-Object {
            $v   = $_
            $cve = ($v.aliases | Where-Object { $_ -like "CVE-*" }) | Select-Object -First 1

            $sev = "UNKNOWN"
            if ($v.database_specific.severity) {
                $sev = $v.database_specific.severity.ToUpper()
            } elseif ($v.severity.Count -gt 0) {
                $scoreStr = $v.severity[0].score -replace ".*/", ""
                try {
                    $n = [float]$scoreStr
                    if     ($n -ge 9.0) { $sev = "CRITICAL" }
                    elseif ($n -ge 7.0) { $sev = "HIGH" }
                    elseif ($n -ge 4.0) { $sev = "MEDIUM" }
                    else                { $sev = "LOW" }
                } catch {}
            }

            $fixed = $v.affected | ForEach-Object {
                $_.ranges | ForEach-Object {
                    $_.events | Where-Object { $_.fixed } |
                    Select-Object -First 1 -ExpandProperty fixed
                }
            } | Select-Object -First 1

            $rows += [PSCustomObject]@{
                ScanType      = $ScanType
                Severity      = $sev
                Package       = $pkg.name
                Version       = $pkg.version
                CVE           = if ($cve) { $cve } else { "N/A" }
                OSV_ID        = $v.id
                Summary       = $v.summary
                Fixed_Version = if ($fixed) { $fixed } else { "No fix yet" }
                OSV_Link      = "https://osv.dev/vulnerability/" + $v.id
                NVD_Link      = if ($cve) { "https://nvd.nist.gov/vuln/detail/" + $cve } else { "N/A" }
            }
        }
    }
}

# Sort by severity
$sorted = $rows | Sort-Object @{
    Expression = {
        switch ($_.Severity) {
            "CRITICAL" { 0 }
            "HIGH"     { 1 }
            "MEDIUM"   { 2 }
            "LOW"      { 3 }
            default    { 4 }
        }
    }
}

$sorted | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8

# Print summary
$c = ($rows | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$h = ($rows | Where-Object { $_.Severity -eq "HIGH" }).Count
$m = ($rows | Where-Object { $_.Severity -eq "MEDIUM" }).Count
$l = ($rows | Where-Object { $_.Severity -eq "LOW" }).Count

Write-Host ""
Write-Host "  [$ScanType Scan Summary]"
Write-Host "  Total : $($rows.Count)  |  Critical: $c  High: $h  Medium: $m  Low: $l"

# Top 5 affected packages
Write-Host "  Top packages:"
$rows | Group-Object Package | Sort-Object Count -Descending |
    Select-Object -First 5 |
    ForEach-Object { Write-Host "    $($_.Count)x  $($_.Name)" }
Write-Host ""
