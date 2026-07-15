param(
    [ValidateRange(1, 65535)]
    [int]$Port = 8765
)

$ErrorActionPreference = "Stop"
$entrypoint = Join-Path $PSScriptRoot "panos-toolbox.py"
if (-not (Test-Path -LiteralPath $entrypoint -PathType Leaf)) {
    throw "Brak entrypointu: $entrypoint"
}

Write-Host "PanOS Toolbox: http://127.0.0.1:$Port/"
Write-Host "Zatrzymanie: Ctrl+C"
if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 $entrypoint serve --port $Port
}
elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python $entrypoint serve --port $Port
}
else {
    throw "Nie znaleziono Python 3 w PATH (py ani python)."
}
exit $LASTEXITCODE
