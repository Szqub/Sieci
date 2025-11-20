<#
.SYNOPSIS
    Generuje filtry LDAP (memberof=...) dla grup AD z pliku.
.DESCRIPTION
    Skrypt pobiera nazwy grup z pliku ad_groups.txt.
    Dla każdej grupy sprawdza, czy ma członków.
    Jeśli tak, pobiera jej DistinguishedName (CN) i tworzy filtr.
    Filtry są grupowane w bloki OR (|...) po maksymalnie 6 sztuk.
#>

$inputFile = "$PSScriptRoot\ad_groups.txt"

# Sprawdzenie czy plik istnieje
if (-not (Test-Path $inputFile)) {
    Write-Error "Nie znaleziono pliku $inputFile. Utwórz go i wpisz nazwy grup (jedna w wierszu)."
    return
}

# Próba załadowania modułu AD
if (-not (Get-Module -Name ActiveDirectory)) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Warning "Nie można załadować modułu ActiveDirectory. Upewnij się, że jest zainstalowany (RSAT)."
    }
}

$groups = Get-Content $inputFile
$validDNs = @()

Write-Host "Przetwarzanie grup z pliku..." -ForegroundColor Cyan

foreach ($groupName in $groups) {
    $groupName = $groupName.Trim()
    if ([string]::IsNullOrWhiteSpace($groupName)) { continue }

    try {
        # Pobieramy grupę wraz z właściwością Members, aby sprawdzić czy nie jest pusta
        $adGroup = Get-ADGroup -Identity $groupName -Properties Members -ErrorAction Stop
        
        if ($adGroup.Members.Count -gt 0) {
            # Dodajemy DistinguishedName do listy
            $validDNs += $adGroup.DistinguishedName
        }
        else {
            Write-Host "[-] Grupa '$groupName' jest pusta. Pomijam." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Błąd dla grupy '$groupName': $_" -ForegroundColor Red
    }
}

Write-Host "`nGenerowanie filtrów..." -ForegroundColor Cyan

# Dzielimy na bloki po 6
$chunkSize = 6
for ($i = 0; $i -lt $validDNs.Count; $i += $chunkSize) {
    # Obliczamy koniec bieżącego bloku
    $endIndex = $i + $chunkSize - 1
    if ($endIndex -ge $validDNs.Count) { $endIndex = $validDNs.Count - 1 }
    
    $chunk = $validDNs[$i..$endIndex]
    
    if ($chunk.Count -eq 1) {
        # Pojedynczy wpis: (memberof=CN)
        $filter = "(memberof=$($chunk[0]))"
    }
    else {
        # Grupa wpisów z operatorem OR: (| (memberof=CN1)(memberof=CN2)... )
        $parts = $chunk | ForEach-Object { "(memberof=$_)" }
        $filter = "(|$(-join $parts))"
    }
    
    Write-Host "Blok $([Math]::Floor($i/$chunkSize) + 1):" -ForegroundColor Green
    Write-Output $filter
    Write-Host ""
}
