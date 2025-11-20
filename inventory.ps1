# Hittar alla konfigurations- och loggfiler i hela network_configs-mappen
# Visar filnamn, sökväg, storlek i KB, senaste ändring och filtyp

$path = "network_configs"

Get-ChildItem -Path $path -Recurse -File -Include *.conf, *.rules, *.log |
Select-Object `
    Name, `
@{n = "FullPath"; e = { $_.FullName } }, `
@{n = "SizeKB"; e = { [math]::Round($_.Length / 1KB, 1) } }, `
@{n = "LastModified"; e = { $_.LastWriteTime } }, `
@{n = "Extension"; e = { $_.Extension } } |
Export-Csv "lista-konfig-och-loggfiler.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Färdigt! Filen lista-konfig-och-loggfiler.csv skapad."

# Visar alla filer som har ändrats de senaste 7 dagarna (räknat från 2024-10-14)

$path = "network_configs"
$now = Get-Date "2024-10-14"     # basdatum enligt övningen
$weekAgo = $now.AddDays(-7)      # sju dagar bakåt

Get-ChildItem -Path $path -Recurse -File |
Where-Object { $_.LastWriteTime -gt $weekAgo } |
Sort-Object LastWriteTime -Descending |
Select-Object `
    Name, `
@{n = "LastModified"; e = { $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm") } }, `
@{n = "FullPath"; e = { $_.FullName } } |
Export-Csv "senaste-7-dagarna.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Färdigt! Filen senaste-7-dagarna.csv skapad."

# Grupperar alla filer efter filtyp (extension)
# Räknar hur många det finns och total storlek i MB

$path = "network_configs"

Get-ChildItem -Path $path -Recurse -File |
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


# Hittar de 5 största loggfilerna i logs-mappen
# Visar filnamn och storlek i MB

$path = "network_configs\logs"

Get-ChildItem -Path $path -Recurse -File -Include *.log |
Sort-Object Length -Descending |
Select-Object -First 5 `
@{n = "FileName"; e = { $_.Name } }, `
@{n = "SizeMB"; e = { [math]::Round($_.Length / 1MB, 2) } }, `
@{n = "FullPath"; e = { $_.FullName } } |
Export-Csv "storsta-loggfiler.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Färdigt! Filen storsta-loggfiler.csv skapad."

# Hittar alla IP-adresser i .conf-filer under network_configs
# Skriver ut en lista med unika IP-adresser till en CSV-fil

$path = "network_configs"

# Enkel regex som matchar IP-adresser (t.ex. 192.168.1.1)
$ipPattern = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

Get-ChildItem -Path $path -Recurse -File -Include *.conf |
Select-String -Pattern $ipPattern -AllMatches |
ForEach-Object {
    # Går igenom alla träffar på raden och tar själva IP-texten
    $_.Matches.Value
} |
Sort-Object -Unique |
Select-Object @{n = "IPAddress"; e = { $_ } } |
Export-Csv "unika-ip-adresser-i-konfig.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Färdigt! Filen unika-ip-adresser-i-konfig.csv skapad."

# Räknar hur många gånger ERROR, FAILED och DENIED finns i varje loggfil
# Skriver en rad per loggfil med alla tre räknare

$path = "network_configs\logs"

# Orden vi letar efter i loggfilerna
$patterns = @("ERROR", "FAILED", "DENIED")

Get-ChildItem -Path $path -Recurse -File -Include *.log |
ForEach-Object {
    $file = $_

    # Skapar en rad (objekt) där vi lagrar resultatet
    $row = [ordered]@{
        FileName = $file.Name
        FullPath = $file.FullName
    }

    foreach ($p in $patterns) {
        # Select-String söker efter texten i filen
        # -AllMatches gör att alla träffar räknas, inte bara första
        $count = (Select-String -Path $file.FullName -Pattern $p -AllMatches | Measure-Object).Count
        $row[$p] = $count
    }

    [pscustomobject]$row
} |
Export-Csv "loggfel-per-fil.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Färdigt! Filen loggfel-per-fil.csv skapad."

# Skapar config_inventory.csv med alla konfigurationsfiler
# Tar med filnamn, sökväg inuti network_configs, storlek och senast ändrad

$basePath = (Resolve-Path "network_configs").Path

# Hjälpfunktion för att få sökväg "inuti" network_configs,
# t.ex. network_configs\routers\RT-EDGE-01.conf
function Get-RelativePathInsideNetworkConfigs {
    param(
        [string]$fullPath
    )

    # Ersätter den riktiga bas-sökvägen (C:\...\network_configs)
    # med bara texten "network_configs"
    return $fullPath.Replace($basePath, "network_configs")
}

Get-ChildItem -Path $basePath -Recurse -File -Include *.conf, *.rules |
Select-Object `
@{n = "FileName"; e = { $_.Name } }, `
@{n = "FullPath"; e = { Get-RelativePathInsideNetworkConfigs $_.FullName } }, `
@{n = "SizeKB"; e = { [math]::Round($_.Length / 1KB, 1) } }, `
@{n = "LastModified"; e = { $_.LastWriteTime } } |
Export-Csv "config_inventory.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Färdigt! Filen config_inventory.csv skapad."

# Söker efter säkerhetsproblem i konfigurationsfiler
# Sparar resultatet i sakerhetsproblem-i-konfig.csv

$basePath = "network_configs"

# Regex för olika typer av problem
# enable password utan kryptering
$enablePasswordPattern = '(?i)^\s*enable\s+password\s+(\S+)'

# password eller secret följt av ett värde (troligen klartext)
$passwordOrSecretPattern = '(?i)\b(password|secret)\s+(\S+)\b'

# SNMP community "public" eller "private"
$snmpCommunityPattern = '(?i)snmp(-server)?\s+community\s+(public|private)\b'

# Enkel funktion som kollar en fil i taget
function Find-SecurityIssues {
    param(
        [string]$Path
    )

    $results = @()
    $lineNumber = 0

    # Läser filen rad för rad
    foreach ($line in Get-Content -Path $Path -ErrorAction SilentlyContinue) {
        $lineNumber++

        # Kollar efter "enable password"
        if ($line -match $enablePasswordPattern) {
            $results += [pscustomobject]@{
                File  = $Path
                Line  = $lineNumber
                Issue = "Enable password (ej krypterad)"
                Text  = $line.Trim()
            }
        }

        # Kollar efter password/secret i klartext
        if ($line -match $passwordOrSecretPattern) {
            # Liten enkel filter: hoppa över typiska hashade "secret 5"
            if ($line -notmatch '(?i)\bsecret\s+(5|8|9)\b') {
                $results += [pscustomobject]@{
                    File  = $Path
                    Line  = $lineNumber
                    Issue = "Klartext password/secret"
                    Text  = $line.Trim()
                }
            }
        }

        # Kollar efter SNMP public/private
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

# Hittar alla relevanta konfig-filer (.conf och .rules)
$files = Get-ChildItem -Path $basePath -Recurse -File -Include *.conf, *.rules

$allFindings = @()

foreach ($file in $files) {
    $allFindings += Find-SecurityIssues -Path $file.FullName
}

# Omvandla till CSV-vänlig form
$allFindings |
Select-Object `
@{n = "File"; e = { $_.File } }, `
@{n = "Line"; e = { $_.Line } }, `
@{n = "Issue"; e = { $_.Issue } }, `
@{n = "Text"; e = { $_.Text } } |
Export-Csv "sakerhetsproblem-i-konfig.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Färdigt! Filen sakerhetsproblem-i-konfig.csv skapad."

# Skapar en enkel security_audit.txt med logganalys och säkerhetsfynd

$basePath = (Resolve-Path "network_configs").Path
$logsPath = Join-Path $basePath "logs"
$backupsPath = Join-Path $basePath "backups"

# Basdatum enligt övningen (kan vara bra att nämna i rapporten)
$now = Get-Date "2024-10-14"

# --- Del 1: Sammanfattning av ERROR i loggfiler ---

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

# --- Del 2: Misslyckade inloggningar (FAILED) per IP ---

# Enkel IP-regex (räcker i denna kurs)
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

# --- Del 3: Svaga konfigurationer (återanvänder mönstren från första skriptet) ---

$enablePasswordPattern = '(?i)^\s*enable\s+password\s+(\S+)'
$passwordOrSecretPattern = '(?i)\b(password|secret)\s+(\S+)\b'
$snmpCommunityPattern = '(?i)snmp(-server)?\s+community\s+(public|private)\b'

function Find-SecurityIssues {
    param([string]$Path)

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

$configFiles = Get-ChildItem -Path $basePath -Recurse -File -Include *.conf, *.rules
$securityFindings = @()
foreach ($cf in $configFiles) {
    $securityFindings += Find-SecurityIssues -Path $cf.FullName
}

$securityByFile = $securityFindings |
Group-Object File |
Select-Object `
@{n = "File"; e = { $_.Name } }, `
@{n = "Issues"; e = { $_.Count } }

# --- Del 4: Filer utan backup ---

# Alla konfigfiler (original) – vi exkluderar både backups och baseline
$allConfigFiles = Get-ChildItem -Path $basePath -Recurse -File -Include *.conf, *.rules |
Where-Object {
    $_.FullName -notlike "*\backups\*" -and
    $_.FullName -notlike "*\baseline\*"
}

# Alla backup-filer
$backupFiles = Get-ChildItem -Path $backupsPath -Recurse -File -Include *.conf, *.rules

# Lista över endast filnamn i backup
$backupNames = $backupFiles.Name

# Hitta filer som saknar backup genom att jämföra filnamn
$missingBackup = $allConfigFiles |
Where-Object { $backupNames -notcontains $_.Name } |
Select-Object @{n = "FileName"; e = { $_.Name } }



# --- Bygg security_audit.txt ---

$reportPath = "security_audit.txt"

$lines = @()

$lines += "================================================================================"
$lines += "                     SECURITY AUDIT REPORT - TechCorp AB"
$lines += "================================================================================"
$lines += ("Generated: {0}" -f $now.ToString("yyyy-MM-dd HH:mm:ss"))
$lines += "Audit Path: ./network_configs/"
$lines += ""

# ============================
# EXECUTIVE SUMMARY
# ============================
$lines += "EXECUTIVE SUMMARY"
$lines += "--------------------------------------------------------------------------------"

# Nyckeltal till sammanfattningen
$totalFailedAttempts = ($failedSummary | Measure-Object Attempts -Sum).Sum
$totalSecurityFindings = $securityFindings.Count
$totalMissingBackups = $missingBackup.Count

$lines += ("• Total ERROR events in logs: {0}" -f $totalErrors)
$lines += ("• Total FAILED login attempts: {0}" -f $totalFailedAttempts)
$lines += ("• Total security findings in configs: {0}" -f $totalSecurityFindings)
$lines += ("• Config files missing backup: {0}" -f $totalMissingBackups)
$lines += ""

# Kort sammanfattningstext
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

# ============================
# LOG ANALYSIS - ERROR SUMMARY
# ============================
$lines += "LOG ANALYSIS - ERROR SUMMARY"
$lines += "--------------------------------------------------------------------------------"
$lines += ("Total ERROR events: {0}" -f $totalErrors)
$lines += ""

foreach ($row in $errorsPerFile | Where-Object { $_.Errors -gt 0 }) {
    $lines += ("• {0} : {1} errors" -f $row.FileName, $row.Errors)
}
$lines += ""

# ============================
# FAILED LOGIN ATTEMPTS
# ============================
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

# ============================
# CONFIGURATION SECURITY FINDINGS
# ============================
$lines += "CONFIGURATION SECURITY FINDINGS"
$lines += "--------------------------------------------------------------------------------"
if ($securityFindings.Count -gt 0) {
    $lines += ("Total findings: {0}" -f $securityFindings.Count)
    $lines += ""
    
    # Gruppera på fil och visa filnamn (utan path)
    $grouped = $securityFindings | Group-Object File
    foreach ($g in $grouped) {
        # t.ex. RT-EDGE-01.conf eller bara RT-EDGE-01
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

# ============================
# FILES WITHOUT BACKUP
# ============================
$lines += "FILES WITHOUT BACKUP"
$lines += "--------------------------------------------------------------------------------"
if ($missingBackup.Count -gt 0) {
    foreach ($m in $missingBackup) {
        # $m.FileName innehåller t.ex. SW-CORE-01.conf -> vi tar bara enhetsnamnet
        $deviceName = [System.IO.Path]::GetFileNameWithoutExtension($m.FileName)
        $lines += ("• {0}" -f $deviceName)
    }
}
else {
    $lines += "All configuration files appear to be backed up."
}
$lines += ""

# ============================
# RECOMMENDATIONS
# ============================
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

# Skriver rapporten till fil
$lines | Set-Content -Path $reportPath -Encoding UTF8

Write-Host "Färdigt! Filen security_audit.txt skapad."


# Jämför router-konfigurationer mot baseline-router.conf
# Använder Compare-Object för att hitta rader som finns i baseline men saknas i routern

$basePath = (Resolve-Path "network_configs").Path
$baselinePath = Join-Path $basePath "baseline\baseline-router.conf"
$routersPath = Join-Path $basePath "routers"

if (-not (Test-Path $baselinePath)) {
    Write-Host "Hittar inte baseline-router.conf. Kontrollera sökvägen:" $baselinePath
    exit
}

$baselineLines = Get-Content -Path $baselinePath

# Hittar alla routerkonfigar (t.ex. RT-EDGE-01.conf)
$routerFiles = Get-ChildItem -Path $routersPath -File -Filter *.conf

$results = @()

foreach ($router in $routerFiles) {
    $routerLines = Get-Content -Path $router.FullName

    # Compare-Object:
    # -ReferenceObject = baseline
    # -DifferenceObject = router
    # SideIndicator "<=" betyder: finns i baseline men inte i router
    $diff = Compare-Object -ReferenceObject $baselineLines -DifferenceObject $routerLines -IncludeEqual:$false

    $missing = $diff | Where-Object { $_.SideIndicator -eq "<=" }

    foreach ($entry in $missing) {
        # Tar bort tomma rader så vi inte skräpar ned
        if ($entry.InputObject.Trim().Length -gt 0) {
            $results += [pscustomobject]@{
                RouterFile  = $router.Name
                MissingLine = $entry.InputObject.Trim()
            }
        }
    }
}

# Sparar alla avvikelser till CSV
$results |
Export-Csv "baseline-avvikelser-router.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Färdigt! Filen baseline-avvikelser-router.csv skapad."

# Skapar en baseline-rapport för routerkonfigurationer
# Jämför varje router-*.conf mot baseline\baseline-router.conf
# Skriver resultat till baseline_report.txt med snygg layout

$basePath = (Resolve-Path "network_configs").Path
$baselinePath = Join-Path $basePath "baseline\baseline-router.conf"
$routersPath = Join-Path $basePath "routers"

$now = Get-Date "2024-10-14"

if (-not (Test-Path $baselinePath)) {
    Write-Host "Hittar inte baseline-router.conf. Kontrollera sökvägen:" $baselinePath
    exit
}

# Läs baseline och routerfiler OCH ta bort kommentarrader
$baselineLines = Get-Content -Path $baselinePath |
Where-Object { $_.Trim() -notmatch '^!' -and $_.Trim() -ne "" }

$routerLines = Get-Content -Path $router.FullName |
Where-Object { $_.Trim() -notmatch '^!' -and $_.Trim() -ne "" }


$deviations = @()

foreach ($router in $routerFiles) {
    $routerLines = Get-Content -Path $router.FullName

    # Compare-Object:
    # "<=" betyder: raden finns i baseline men inte i routern
    $diff = Compare-Object -ReferenceObject $baselineLines -DifferenceObject $routerLines -IncludeEqual:$false
    $missing = $diff | Where-Object { $_.SideIndicator -eq "<=" }

    foreach ($entry in $missing) {
        if ($entry.InputObject.Trim().Length -gt 0) {
            $deviations += [pscustomobject]@{
                RouterFile  = $router.Name
                MissingLine = $entry.InputObject.Trim()
            }
        }
    }
}

# Gruppera avvikelser per router
$groupedDeviations = $deviations | Group-Object RouterFile

$reportPath = "baseline_report.txt"
$lines = @()

$lines += "================================================================================"
$lines += "                    BASELINE COMPLIANCE REPORT - ROUTERS"
$lines += "================================================================================"
$lines += ("Generated: {0}" -f $now.ToString("yyyy-MM-dd HH:mm:ss"))
$lines += "Audit Path: ./network_configs/routers/"
$lines += "Baseline:   ./network_configs/baseline/baseline-router.conf"
$lines += ""

# Nyckeltal till sammanfattning
$totalRouters = $routerFiles.Count
$totalDeviationLines = $deviations.Count
$routersWithIssues = ($groupedDeviations | Measure-Object).Count

# ============================
# EXECUTIVE SUMMARY
# ============================
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

# ============================
# DETAILED DEVIATIONS PER ROUTER
# ============================
$lines += "DETAILED DEVIATIONS PER ROUTER"
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

# ============================
# RECOMMENDATIONS
# ============================
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
