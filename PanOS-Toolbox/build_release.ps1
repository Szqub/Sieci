param(
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$toolboxRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $toolboxRoot "..")).Path
$frontend = Join-Path $toolboxRoot "frontend"
$backendRoot = Join-Path $toolboxRoot "backend"
$backendPackage = Join-Path $toolboxRoot "backend\panos_toolbox"
$requirements = Join-Path $toolboxRoot "backend\requirements.txt"
$legacyPackage = Join-Path $repoRoot "panorama_cleaner\panorama_cleanup"
$static = Join-Path $backendPackage "static"
$staging = Join-Path $toolboxRoot ".release-staging"
$releaseDir = Join-Path $toolboxRoot "release"

foreach ($required in @($frontend, $backendPackage, $legacyPackage)) {
    if (-not (Test-Path -LiteralPath $required -PathType Container)) {
        throw "Required directory is missing: $required"
    }
}
if (-not (Test-Path -LiteralPath $requirements -PathType Leaf)) {
    throw "Required file is missing: $requirements"
}

function Invoke-BuildPython {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $launcher = Get-Command py -ErrorAction SilentlyContinue
    if ($launcher) {
        & $launcher.Source -3 @Arguments
    }
    else {
        $python = Get-Command python -ErrorAction SilentlyContinue
        if (-not $python) {
            throw "Python 3 was not found (neither py nor python)."
        }
        & $python.Source @Arguments
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Python build step failed with exit code $LASTEXITCODE."
    }
}

Push-Location $frontend
try {
    npm ci
    if (-not $SkipTests) {
        npm test
    }
    npm run build
}
finally {
    Pop-Location
}

if (Test-Path -LiteralPath $static) {
    $resolvedStatic = (Resolve-Path -LiteralPath $static).Path
    if (-not $resolvedStatic.StartsWith($toolboxRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a directory outside PanOS-Toolbox: $resolvedStatic"
    }
    Remove-Item -LiteralPath $resolvedStatic -Recurse -Force
}
New-Item -ItemType Directory -Path $static -Force | Out-Null
Copy-Item -Path (Join-Path $frontend "dist\*") -Destination $static -Recurse -Force

if (Test-Path -LiteralPath $staging) {
    $resolvedStaging = (Resolve-Path -LiteralPath $staging).Path
    if (-not $resolvedStaging.StartsWith($toolboxRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a directory outside PanOS-Toolbox: $resolvedStaging"
    }
    Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
}

$packageRoot = Join-Path $staging "PanOS-Toolbox"
$packageBackend = Join-Path $packageRoot "backend\panos_toolbox"
$packageVendorRoot = Join-Path $packageRoot "backend\vendor"
$packageVendor = Join-Path $packageVendorRoot "panorama_cleaner\panorama_cleanup"
New-Item -ItemType Directory -Path $packageBackend -Force | Out-Null
New-Item -ItemType Directory -Path $packageVendor -Force | Out-Null

Invoke-BuildPython -Arguments @(
    "-m", "pip", "install",
    "--disable-pip-version-check",
    "--no-compile",
    "--target", $packageVendorRoot,
    "-r", $requirements
)
# The selected dependencies have pure-Python fallbacks. Remove every extension
# built for the build-host ABI so the zip remains usable with supported Python
# 3.10+ runtimes on Windows.
Get-ChildItem -LiteralPath $packageVendorRoot -File -Filter "*.pyd" -Recurse -ErrorAction SilentlyContinue |
    Remove-Item -Force
Get-ChildItem -LiteralPath $packageVendorRoot -Directory -Filter "__pycache__" -Recurse -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force

if (-not $SkipTests) {
    $previousPythonPath = $env:PYTHONPATH
    $env:PYTHONPATH = @(
        $packageVendorRoot
        $backendRoot
        (Join-Path $repoRoot "panorama_cleaner")
    ) -join [System.IO.Path]::PathSeparator
    try {
        Push-Location $backendRoot
        try {
            Invoke-BuildPython -Arguments @("-m", "unittest", "discover", "-s", "tests", "-v")
        }
        finally {
            Pop-Location
        }

        Push-Location (Join-Path $repoRoot "panorama_cleaner")
        try {
            Invoke-BuildPython -Arguments @("-m", "unittest", "discover", "-s", "tests", "-v")
        }
        finally {
            Pop-Location
        }
    }
    finally {
        $env:PYTHONPATH = $previousPythonPath
    }
}

Get-ChildItem -LiteralPath $backendPackage -File -Filter "*.py" |
    Copy-Item -Destination $packageBackend
Copy-Item -LiteralPath $static -Destination $packageBackend -Recurse
Get-ChildItem -LiteralPath $legacyPackage -File -Filter "*.py" |
    Copy-Item -Destination $packageVendor

foreach ($file in @(
    "panos-toolbox.py",
    "panos_toolbox.py",
    "README.md",
    "LAB_VALIDATION.md",
    "panorama_host.txt.example",
    "ip.txt.example",
    "start_toolbox.ps1"
)) {
    Copy-Item -LiteralPath (Join-Path $toolboxRoot $file) -Destination $packageRoot
}
Copy-Item -LiteralPath $requirements -Destination (Join-Path $packageRoot "backend\requirements.txt")

$doctorStore = Join-Path $staging "doctor-sessions"
Invoke-BuildPython -Arguments @(
    (Join-Path $packageRoot "panos-toolbox.py"),
    "doctor",
    "--session-dir", $doctorStore
)
if (Test-Path -LiteralPath $doctorStore) {
    Remove-Item -LiteralPath $doctorStore -Recurse -Force
}

# The packaged doctor imports the staged application and therefore creates
# bytecode caches. Never ship build-host bytecode or cache directories.
Get-ChildItem -LiteralPath $packageRoot -Directory -Filter "__pycache__" -Recurse -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force
Get-ChildItem -LiteralPath $packageRoot -File -Filter "*.pyc" -Recurse -ErrorAction SilentlyContinue |
    Remove-Item -Force
Get-ChildItem -LiteralPath $packageRoot -File -Filter "*.pyo" -Recurse -ErrorAction SilentlyContinue |
    Remove-Item -Force

foreach ($requiredPackageFile in @(
    (Join-Path $packageRoot "panos-toolbox.py")
    (Join-Path $packageBackend "__init__.py")
    (Join-Path $packageBackend "static\index.html")
    (Join-Path $packageVendorRoot "flask\__init__.py")
    (Join-Path $packageVendor "__init__.py")
)) {
    if (-not (Test-Path -LiteralPath $requiredPackageFile -PathType Leaf)) {
        throw "Release staging invariant failed; required file is missing: $requiredPackageFile"
    }
}

New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$archive = Join-Path $releaseDir "PanOS-Toolbox-$stamp.zip"
Compress-Archive -Path $packageRoot -DestinationPath $archive -CompressionLevel Optimal

$resolvedStaging = (Resolve-Path -LiteralPath $staging).Path
if (-not $resolvedStaging.StartsWith($toolboxRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean a directory outside PanOS-Toolbox: $resolvedStaging"
}
Remove-Item -LiteralPath $resolvedStaging -Recurse -Force

Write-Host "Release package ready: $archive"
