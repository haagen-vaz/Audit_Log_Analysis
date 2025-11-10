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
