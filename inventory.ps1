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
