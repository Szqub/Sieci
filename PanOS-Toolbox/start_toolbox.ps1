param(
    [ValidateRange(1, 65535)]
    [int]$Port = 8765
)

$ErrorActionPreference = "Stop"
$entrypoint = Join-Path $PSScriptRoot "panos-toolbox.py"
$sessionRoot = Join-Path $PSScriptRoot "backupy\sessions"
if (-not (Test-Path -LiteralPath $entrypoint -PathType Leaf)) {
    throw "Brak entrypointu: $entrypoint"
}
$vendorFlask = Join-Path $PSScriptRoot "backend\vendor\flask\__init__.py"
$vendorWerkzeug = Join-Path $PSScriptRoot "backend\vendor\werkzeug\__init__.py"
$staticIndex = Join-Path $PSScriptRoot "backend\panos_toolbox\static\index.html"
foreach ($required in @($vendorFlask, $vendorWerkzeug, $staticIndex)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw (
            "To nie jest kompletna paczka portable. Brakuje: $required. " +
            "Pobierz ZIP z https://github.com/Szqub/Sieci/releases/latest, " +
            "wybierz 'Wyodrębnij wszystkie' i nie instaluj Flask przez pip."
        )
    }
}

Write-Host "PanOS Toolbox: http://127.0.0.1:$Port/"
Write-Host "Trwale backupy sesji: $sessionRoot"
Write-Host "Zatrzymanie: Ctrl+C"
if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 -I -S $entrypoint serve --port $Port --session-dir $sessionRoot
}
elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python -I -S $entrypoint serve --port $Port --session-dir $sessionRoot
}
else {
    throw "Nie znaleziono Python 3 w PATH (py ani python)."
}
exit $LASTEXITCODE
