[CmdletBinding()]
param(
    [switch]$Doctor,
    [ValidateRange(1, 65535)]
    [int]$Port = 8765
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$toolboxRoot = $PSScriptRoot
$entryPoint = Join-Path $toolboxRoot "panos-toolbox.py"
$requiredFiles = @(
    (Join-Path $toolboxRoot "backend\vendor\flask\__init__.py"),
    (Join-Path $toolboxRoot "backend\vendor\werkzeug\__init__.py"),
    (Join-Path $toolboxRoot "backend\panos_toolbox\static\index.html"),
    $entryPoint
)
foreach ($required in $requiredFiles) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Paczka jest niekompletna albo uruchomiona wewnątrz ZIP. Brak: $required"
    }
}

function Resolve-ToolboxPython {
    if ($env:PANOS_TOOLBOX_PYTHON) {
        $configured = [System.IO.Path]::GetFullPath($env:PANOS_TOOLBOX_PYTHON)
        if (-not (Test-Path -LiteralPath $configured -PathType Leaf)) {
            throw "PANOS_TOOLBOX_PYTHON nie wskazuje istniejącego pliku: $configured"
        }
        if ([System.IO.Path]::GetExtension($configured) -ne ".exe") {
            throw "PANOS_TOOLBOX_PYTHON musi wskazywać python.exe albo py.exe."
        }
        return $configured
    }

    $candidates = @(
        (Join-Path $env:SystemRoot "py.exe"),
        (Join-Path $env:LocalAppData "Programs\Python\Launcher\py.exe")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    $roots = @(
        (Join-Path $env:LocalAppData "Programs\Python"),
        $env:ProgramFiles
    )
    foreach ($root in $roots) {
        if (-not $root -or -not (Test-Path -LiteralPath $root -PathType Container)) {
            continue
        }
        $python = Get-ChildItem -LiteralPath $root -Directory -Filter "Python*" -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending |
            ForEach-Object { Join-Path $_.FullName "python.exe" } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            Select-Object -First 1
        if ($python) {
            return $python
        }
    }
    throw "Nie znaleziono zatwierdzonego Python 3. Ustaw PANOS_TOOLBOX_PYTHON na pełną ścieżkę python.exe."
}

$python = Resolve-ToolboxPython
$pythonArguments = @()
if ([System.IO.Path]::GetFileName($python) -ieq "py.exe") {
    $pythonArguments += "-3"
}
$pythonArguments += @("-I", "-B", "-S", $entryPoint)
if ($Doctor) {
    $pythonArguments += "doctor"
}
else {
    $pythonArguments += @("serve", "--port", [string]$Port)
}

Write-Host "PanOS Toolbox użyje: $python"
if (-not $Doctor) {
    Write-Host "Bezpieczny link sesji zostanie otwarty automatycznie przez backend."
    Write-Host "Trwałe dane lokalne: $env:LOCALAPPDATA\PanOS Toolbox"
}
& $python @pythonArguments
exit $LASTEXITCODE
