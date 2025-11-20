# -------------------------------------------------------------------
# Grundvägar (paths) för hela skriptet
# -------------------------------------------------------------------
$rootPath = (Resolve-Path "network_configs").Path
$logsPath = Join-Path $rootPath "logs"
$backupsPath = Join-Path $rootPath "backups"
$routersPath = Join-Path $rootPath "routers"
$baselinePath = Join-Path $rootPath "baseline\baseline-router.conf"

# Basdatum enligt övningen
$now = Get-Date "2024-10-14"

# -------------------------------------------------------------------
# Lista alla konfig- och loggfiler
# -------------------------------------------------------------------
Get-ChildItem -Path $rootPath -Recurse -File -Include *.conf, *.rules, *.log |
Select-Object `
    Name, `
@{n = "FullPath"; e = { $_.FullName } }, `
@{n = "SizeKB"; e = { [math]::Round($_.Length / 1KB, 1) } }, `
@{n = "LastModified"; e = { $_.LastWriteTime } }, `
@{n = "Extension"; e = { $_.Extension } } |
Export-Csv "lista-konfig-och-loggfiler.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Färdigt! Filen lista-konfig-och-loggfiler.csv skapad."

# -------------------------------------------------------------------
# Filer ändrade senaste 7 dagarna (från 2024-10-14)
# -------------------------------------------------------------------
$weekAgo = $now.AddDays(-7)

Get-ChildItem -Path $rootPath -Recurse -File |
Where-Object { $_.LastWriteTime -gt $weekAgo } |
Sort-Object LastWriteTime -Descending |
Select-Object `
    Name, `
@{n = "LastModified"; e = { $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm") } }, `
@{n = "FullPath"; e = { $_.FullName } } |
Export-Csv "senaste-7-dagarna.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Färdigt! Filen senaste-7-dagarna.csv skapad."

# -------------------------------------------------------------------
# Filtyper och total storlek
# -------------------------------------------------------------------
Get-ChildItem -Path $rootPath -Recurse -File |
Group-Object Extension |
Sort-Object Name |
ForEach-Object {
    [pscustomobject]@{
        FileType    = if ($_.Name) { $_.Name } else { "<none>" }
        Count       = $_.Count
        TotalSizeMB = [math]::Round((($_.Group | Measure-Object Length -Sum).Sum) / 1MB, 2)
    }
} |
Export-Csv "filer-per-typ-och-storlek.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Färdigt! Filen filer-per-typ-och-storlek.csv skapad."

# -------------------------------------------------------------------
# 5 största loggfilerna
# -------------------------------------------------------------------
Get-ChildItem -Path $logsPath -Recurse -File -Include *.log |
Sort-Object Length -Descending |
Select-Object -First 5 `
@{n = "FileName"; e = { $_.Name } }, `
@{n = "SizeMB"; e = { [math]::Round($_.Length / 1MB, 2) } }, `
@{n = "FullPath"; e = { $_.FullName } } |
Export-Csv "storsta-loggfiler.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Färdigt! Filen storsta-loggfiler.csv skapad."

# -------------------------------------------------------------------
# Unika IP-adresser i .conf
# -------------------------------------------------------------------
$ipPattern = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

Get-ChildItem -Path $rootPath -Recurse -File -Include *.conf |
Select-String -Pattern $ipPattern -AllMatches |
ForEach-Object {
    $_.Matches.Value
} |
Sort-Object -Unique |
Select-Object @{n = "IPAddress"; e = { $_ } } |
Export-Csv "unika-ip-adresser-i-konfig.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Färdigt! Filen unika-ip-adresser-i-konfig.csv skapad."

# -------------------------------------------------------------------
# ERROR / FAILED / DENIED per loggfil
# -------------------------------------------------------------------
$patterns = @("ERROR", "FAILED", "DENIED")

Get-ChildItem -Path $logsPath -Recurse -File -Include *.log |
ForEach-Object {
    $file = $_

    $row = [ordered]@{
        FileName = $file.Name
        FullPath = $file.FullName
    }

    foreach ($p in $patterns) {
        $count = (Select-String -Path $file.FullName -Pattern $p -AllMatches | Measure-Object).Count
        $row[$p] = $count
    }

    [pscustomobject]$row
} |
Export-Csv "loggfel-per-fil.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Färdigt! Filen loggfel-per-fil.csv skapad."

# -------------------------------------------------------------------
# config_inventory.csv (relativ sökväg inuti network_configs)
# -------------------------------------------------------------------
function Get-RelativePathInsideNetworkConfigs {
    param(
        [string]$fullPath
    )
    return $fullPath.Replace($rootPath, "network_configs")
}

Get-ChildItem -Path $rootPath -Recurse -File -Include *.conf, *.rules |
Select-Object `
@{n = "FileName"; e = { $_.Name } }, `
@{n = "FullPath"; e = { Get-RelativePathInsideNetworkConfigs $_.FullName } }, `
@{n = "SizeKB"; e = { [math]::Round($_.Length / 1KB, 1) } }, `
@{n = "LastModified"; e = { $_.LastWriteTime } } |
Export-Csv "config_inventory.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Färdigt! Filen config_inventory.csv skapad."

# -------------------------------------------------------------------
# Funktion: Find-SecurityIssues (återanvänds längre ned)
# -------------------------------------------------------------------
$enablePasswordPattern = '(?i)^\s*enable\s+password\s+(\S+)'
$passwordOrSecretPattern = '(?i)\b(password|secret)\s+(\S+)\b'
$snmpCommunityPattern = '(?i)snmp(-server)?\s+community\s+(public|private)\b'

function Find-SecurityIssues {
    param(
        [string]$Path
    )

    $results = @()
    $lineNumber = 0

    foreach ($line in Get-Content -Path $Path -ErrorAction SilentlyContinue) {
        $lineNumber++

        if ($line -match $enablePasswordPattern) {
            $results += [pscustomobject]@{
                File  = $Path
                Line  = $lineNumber
                Issue = "Enable password (ej krypterad)"
                Text  = $line.Trim()
            }
        }

        if ($line -match $passwordOrSecretPattern) {
            if ($line -notmatch '(?i)\bsecret\s+(5|8|9)\b') {
                $results += [pscustomobject]@{
                    File  = $Path
                    Line  = $lineNumber
                    Issue = "Klartext password/secret"
                    Text  = $line.Trim()
                }
            }
        }

        if ($line -match $snmpCommunityPattern) {
            $results += [pscustomobject]@{
                File  = $Path
                Line  = $lineNumber
                Issue = "SNMP community public/private"
                Text  = $line.Trim()
            }
        }
    }

    return $results
}

# -------------------------------------------------------------------
# Kör Find-SecurityIssues för alla .conf/.rules och skriv CSV
# -------------------------------------------------------------------
$files = Get-ChildItem -Path $rootPath -Recurse -File -Include *.conf, *.rules
$allFindings = @()

foreach ($file in $files) {
    $allFindings += Find-SecurityIssues -Path $file.FullName
}

$allFindings |
Select-Object `
@{n = "File"; e = { $_.File } }, `
@{n = "Line"; e = { $_.Line } }, `
@{n = "Issue"; e = { $_.Issue } }, `
@{n = "Text"; e = { $_.Text } } |
Export-Csv "sakerhetsproblem-i-konfig.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Färdigt! Filen sakerhetsproblem-i-konfig.csv skapad."

# -------------------------------------------------------------------
# SECURITY AUDIT REPORT (security_audit.txt)
# -------------------------------------------------------------------
# ERROR-sammanfattning
$logFiles = Get-ChildItem -Path $logsPath -Recurse -File -Include *.log

$errorsPerFile = foreach ($log in $logFiles) {
    $count = (Select-String -Path $log.FullName -Pattern "ERROR" -AllMatches | Measure-Object).Count

    [pscustomobject]@{
        FileName = $log.Name
        FullPath = $log.FullName
        Errors   = $count
    }
}
$totalErrors = ($errorsPerFile | Measure-Object Errors -Sum).Sum

# FAILED login per IP
$ipPattern = "\d{1,3}(\.\d{1,3}){3}"

$failedLogins = foreach ($log in $logFiles) {
    Select-String -Path $log.FullName -Pattern "FAILED" -AllMatches |
    ForEach-Object {
        $line = $_.Line
        $ipMatch = [regex]::Match($line, $ipPattern)

        [pscustomobject]@{
            File = $log.Name
            IP   = if ($ipMatch.Success) { $ipMatch.Value } else { "unknown" }
        }
    }
}

$failedSummary = $failedLogins |
Group-Object IP |
Select-Object `
@{n = "IP"; e = { $_.Name } }, `
@{n = "Attempts"; e = { $_.Count } } |
Sort-Object Attempts -Descending

# Säkerhetsfynd i configs (återanvänder Find-SecurityIssues)
$configFiles = Get-ChildItem -Path $rootPath -Recurse -File -Include *.conf, *.rules
$securityFindings = @()
foreach ($cf in $configFiles) {
    $securityFindings += Find-SecurityIssues -Path $cf.FullName
}

# Filer utan backup
$allConfigFiles = Get-ChildItem -Path $rootPath -Recurse -File -Include *.conf, *.rules |
Where-Object {
    $_.FullName -notlike "*\backups\*" -and
    $_.FullName -notlike "*\baseline\*"
}

$backupFiles = Get-ChildItem -Path $backupsPath -Recurse -File -Include *.conf, *.rules
$backupNames = $backupFiles.Name

$missingBackup = $allConfigFiles |
Where-Object { $backupNames -notcontains $_.Name } |
Select-Object @{n = "FileName"; e = { $_.Name } }

# Bygg security_audit.txt
$reportPath = "security_audit.txt"
$lines = @()

$lines += "================================================================================"
$lines += "                     SECURITY AUDIT REPORT - TechCorp AB"
$lines += "================================================================================"
$lines += ("Generated: {0}" -f $now.ToString("yyyy-MM-dd HH:mm:ss"))
$lines += "Audit Path: ./network_configs/"
$lines += ""

# EXECUTIVE SUMMARY
$lines += "EXECUTIVE SUMMARY"
$lines += "--------------------------------------------------------------------------------"

$totalFailedAttempts = ($failedSummary | Measure-Object Attempts -Sum).Sum
$totalSecurityFindings = $securityFindings.Count
$totalMissingBackups = $missingBackup.Count

$lines += ("• Total ERROR events in logs: {0}" -f $totalErrors)
$lines += ("• Total FAILED login attempts: {0}" -f $totalFailedAttempts)
$lines += ("• Total security findings in configs: {0}" -f $totalSecurityFindings)
$lines += ("• Config files missing backup: {0}" -f $totalMissingBackups)
$lines += ""

if ($totalSecurityFindings -gt 0 -or $totalErrors -gt 0 -or $totalFailedAttempts -gt 0 -or $totalMissingBackups -gt 0) {
    $lines += "Summary:"
    if ($totalSecurityFindings -gt 0) {
        $lines += "  - Weak or risky configuration settings were detected and should be fixed."
    }
    if ($totalErrors -gt 0) {
        $lines += "  - System and security logs contain ERROR events that require review."
    }
    if ($totalFailedAttempts -gt 0) {
        $lines += "  - There are failed login attempts that may indicate brute force or misuse."
    }
    if ($totalMissingBackups -gt 0) {
        $lines += "  - Some configuration files appear to lack backup coverage."
    }
}
else {
    $lines += "Summary: No critical issues detected with current checks."
}
$lines += ""
$lines += ""

# LOG ANALYSIS
$lines += "LOG ANALYSIS - ERROR SUMMARY"
$lines += "--------------------------------------------------------------------------------"
$lines += ("Total ERROR events: {0}" -f $totalErrors)
$lines += ""

foreach ($row in $errorsPerFile | Where-Object { $_.Errors -gt 0 }) {
    $lines += ("• {0} : {1} errors" -f $row.FileName, $row.Errors)
}
$lines += ""

# FAILED LOGIN ATTEMPTS
$lines += "FAILED LOGIN ATTEMPTS"
$lines += "--------------------------------------------------------------------------------"
if ($failedSummary.Count -gt 0) {
    foreach ($f in $failedSummary) {
        $lines += ("• {0} attempts from {1}" -f $f.Attempts, $f.IP)
    }
}
else {
    $lines += "No failed login attempts found."
}
$lines += ""

# CONFIGURATION SECURITY FINDINGS
$lines += "CONFIGURATION SECURITY FINDINGS"
$lines += "--------------------------------------------------------------------------------"
if ($securityFindings.Count -gt 0) {
    $lines += ("Total findings: {0}" -f $securityFindings.Count)
    $lines += ""
    $grouped = $securityFindings | Group-Object File
    foreach ($g in $grouped) {
        $fileName = [System.IO.Path]::GetFileNameWithoutExtension($g.Name)
        $lines += ("{0}:" -f $fileName)
        foreach ($entry in $g.Group | Select-Object -First 5) {
            $lines += ("   • Line {0}: {1}" -f $entry.Line, $entry.Text)
        }
        $lines += ""
    }
}
else {
    $lines += "No weak configuration settings detected."
}
$lines += ""

# FILES WITHOUT BACKUP
$lines += "FILES WITHOUT BACKUP"
$lines += "--------------------------------------------------------------------------------"
if ($missingBackup.Count -gt 0) {
    foreach ($m in $missingBackup) {
        $deviceName = [System.IO.Path]::GetFileNameWithoutExtension($m.FileName)
        $lines += ("• {0}" -f $deviceName)
    }
}
else {
    $lines += "All configuration files appear to be backed up."
}
$lines += ""

# RECOMMENDATIONS
$lines += "RECOMMENDATIONS"
$lines += "--------------------------------------------------------------------------------"

if ($securityFindings | Where-Object { $_.Issue -match "Enable password" }) {
    $lines += "• URGENT: Replace 'enable password' with 'enable secret'."
}
if ($securityFindings | Where-Object { $_.Issue -match "Klartext" }) {
    $lines += "• URGENT: Remove or encrypt plaintext passwords/secrets."
}
if ($securityFindings | Where-Object { $_.Issue -match "SNMP" }) {
    $lines += "• HIGH: Avoid using SNMP community strings 'public' or 'private'."
}
if ($missingBackup.Count -gt 0) {
    $lines += "• MEDIUM: Add missing configuration files to backup routines."
}
if ($failedSummary.Count -gt 0) {
    $lines += "• MEDIUM: Monitor repeated failed login attempts by IP."
}
if ($totalErrors -gt 0) {
    $lines += "• MEDIUM: Investigate recurring ERROR events in system logs."
}

$lines += ""
$lines += "================================================================================"
$lines += "                                   END OF REPORT"
$lines += "================================================================================"

$lines | Set-Content -Path $reportPath -Encoding UTF8
Write-Host "Färdigt! Filen security_audit.txt skapad."

# -------------------------------------------------------------------
# BASELINE-JÄMFÖRELSE FÖR ROUTERS
# -------------------------------------------------------------------
function Normalize-ConfigForBaseline {
    param([string]$Path)

    $insideBanner = $false

    Get-Content -Path $Path | ForEach-Object {
        $raw = $_
        $line = $raw.Trim()

        if ($line -like "banner login*") {
            $insideBanner = $true
            return
        }

        if ($insideBanner) {
            if ($line -eq "^C") {
                $insideBanner = $false
                return 'banner login (present)'
            }
            return
        }

        $raw
    }
}

if (-not (Test-Path $baselinePath)) {
    Write-Host "Hittar inte baseline-router.conf. Kontrollera sökvägen:" $baselinePath
    exit
}

$routerFiles = Get-ChildItem -Path $routersPath -File -Filter *.conf

$baselineLinesClean = Normalize-ConfigForBaseline -Path $baselinePath |
Where-Object { $_.Trim() -notmatch '^!' -and $_.Trim() -ne "" }

$results = @()

foreach ($router in $routerFiles) {
    $routerLinesClean = Normalize-ConfigForBaseline -Path $router.FullName |
    Where-Object { $_.Trim() -notmatch '^!' -and $_.Trim() -ne "" }

    $diff = Compare-Object -ReferenceObject $baselineLinesClean -DifferenceObject $routerLinesClean -IncludeEqual:$false
    $missing = $diff | Where-Object { $_.SideIndicator -eq "<=" }

    foreach ($entry in $missing) {
        if ($entry.InputObject.Trim().Length -gt 0) {
            $results += [pscustomobject]@{
                RouterFile  = $router.Name
                MissingLine = $entry.InputObject.Trim()
            }
        }
    }
}

$results |
Export-Csv "baseline-avvikelser-router.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Färdigt! Filen baseline-avvikelser-router.csv skapad."

# baseline_report.txt
$deviations = $results
$groupedDeviations = $deviations | Group-Object RouterFile

$reportPath = "baseline_report.txt"
$lines = @()

$lines += "================================================================================"
$lines += "                 ROUTER BASELINE COMPLIANCE REPORT - TechCorp AB"
$lines += "================================================================================"
$lines += ("Generated: {0}" -f $now.ToString("yyyy-MM-dd HH:mm:ss"))
$lines += "Audit Path: ./network_configs/routers/"
$lines += "Baseline:   ./network_configs/baseline/baseline-router.conf"
$lines += ""

$totalRouters = $routerFiles.Count
$totalDeviationLines = $deviations.Count
$routersWithIssues = ($groupedDeviations | Measure-Object).Count

$lines += "EXECUTIVE SUMMARY"
$lines += "--------------------------------------------------------------------------------"
$lines += ("• Routers checked: {0}" -f $totalRouters)
$lines += ("• Routers with deviations: {0}" -f $routersWithIssues)
$lines += ("• Total missing baseline lines: {0}" -f $totalDeviationLines)
$lines += ""

if ($totalDeviationLines -gt 0) {
    $lines += "Summary:"
    $lines += "  - One or more routers are missing configuration lines that exist in the baseline."
    $lines += "  - Review the detailed list below and update router configurations to match baseline."
}
else {
    $lines += "Summary: All router configurations match the baseline (no missing lines found)."
}
$lines += ""
$lines += ""

$lines += "BASELINE DEVIATIONS PER ROUTER"
$lines += "--------------------------------------------------------------------------------"

if ($totalDeviationLines -gt 0) {
    foreach ($g in $groupedDeviations) {
        $lines += ""
        $lines += ("Router: {0}" -f $g.Name)
        $lines += ("Missing lines compared to baseline:")
        foreach ($entry in $g.Group) {
            $lines += ("   • {0}" -f $entry.MissingLine)
        }
        $lines += ""
    }
}
else {
    $lines += "No deviations detected. Routers appear to comply with the baseline configuration."
}
$lines += ""

$lines += "RECOMMENDATIONS"
$lines += "--------------------------------------------------------------------------------"
if ($totalDeviationLines -gt 0) {
    $lines += "• HIGH: Review each router with missing lines and align its configuration to the baseline."
    $lines += "• MEDIUM: Document any intentional deviations (change management) to avoid confusion later."
}
else {
    $lines += "• Maintain regular comparison against baseline after changes or upgrades."
}
$lines += ""
$lines += "================================================================================"
$lines += "                                   END OF REPORT"
$lines += "================================================================================"

$lines | Set-Content -Path $reportPath -Encoding UTF8

Write-Host "Färdigt! Filen baseline_report.txt skapad."
