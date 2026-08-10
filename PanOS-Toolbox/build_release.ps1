param(
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$requiredPathExt = @(".COM", ".EXE", ".BAT", ".CMD")
$pathExt = @($env:PATHEXT -split ";" | Where-Object { $_ })
foreach ($extension in $requiredPathExt) {
    if ($pathExt -notcontains $extension) {
        $pathExt += $extension
    }
}
$env:PATHEXT = $pathExt -join ";"

$toolboxRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $toolboxRoot "..")).Path
$frontend = Join-Path $toolboxRoot "frontend"
$backendRoot = Join-Path $toolboxRoot "backend"
$backendPackage = Join-Path $toolboxRoot "backend\panos_toolbox"
$requirements = Join-Path $toolboxRoot "backend\requirements.txt"
$adGroupHelper = Join-Path $backendPackage "ad_group_lookup.ps1"
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
if (-not (Test-Path -LiteralPath $adGroupHelper -PathType Leaf)) {
    throw "Required file is missing: $adGroupHelper"
}

function Invoke-BuildPython {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        $executable = $launcher.Source
        $processArguments = @("-3") + $Arguments
    }
    else {
        $python = Get-Command python.exe -ErrorAction SilentlyContinue
        if (-not $python) {
            throw "Python 3 was not found (neither py nor python)."
        }
        $executable = $python.Source
        $processArguments = $Arguments
    }

    # Start-Process provides a reliable exit code both in an ordinary Windows
    # terminal and when this script is started through WSL interoperability.
    $process = Start-Process -FilePath $executable -ArgumentList $processArguments `
        -WorkingDirectory (Get-Location).ProviderPath -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -ne 0) {
        throw "Python build step failed with exit code $($process.ExitCode)."
    }
}

function Invoke-BuildNpm {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if (-not $npm) {
        $npm = Get-Command npm -ErrorAction SilentlyContinue
    }
    if (-not $npm) {
        throw "npm was not found."
    }
    $process = Start-Process -FilePath $npm.Source -ArgumentList $Arguments `
        -WorkingDirectory (Get-Location).ProviderPath -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -ne 0) {
        throw "npm build step failed with exit code $($process.ExitCode)."
    }
}

Push-Location $frontend
try {
    Invoke-BuildNpm -Arguments @("ci")
    if (-not $SkipTests) {
        Invoke-BuildNpm -Arguments @("test")
    }
    Invoke-BuildNpm -Arguments @("run", "build")
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
Get-ChildItem -LiteralPath $backendPackage -File -Filter "*.ps1" |
    Copy-Item -Destination $packageBackend
Copy-Item -LiteralPath $static -Destination $packageBackend -Recurse
Get-ChildItem -LiteralPath $legacyPackage -File -Filter "*.py" |
    Copy-Item -Destination $packageVendor

foreach ($file in @(
    "panos-toolbox.py",
    "panos_toolbox.py",
    "README.md",
    "ROZPAKUJ_I_URUCHOM.txt",
    "LAB_VALIDATION.md",
    "start_toolbox.cmd",
    "start_toolbox.ps1"
)) {
    Copy-Item -LiteralPath (Join-Path $toolboxRoot $file) -Destination $packageRoot
}
Copy-Item -LiteralPath $requirements -Destination (Join-Path $packageRoot "backend\requirements.txt")

$doctorStore = Join-Path $staging "doctor-sessions"
Invoke-BuildPython -Arguments @(
    "-I",
    "-S",
    (Join-Path $packageRoot "panos-toolbox.py"),
    "doctor",
    "--session-dir", $doctorStore
)
if (Test-Path -LiteralPath $doctorStore) {
    Remove-Item -LiteralPath $doctorStore -Recurse -Force
}

# Validate the exact double-click launcher shipped to the target machine.
$cmdLauncher = Join-Path $packageRoot "start_toolbox.cmd"
$launcherStdout = Join-Path $staging "launcher-doctor.stdout.log"
$launcherStderr = Join-Path $staging "launcher-doctor.stderr.log"
$launcherProcess = Start-Process -FilePath $cmdLauncher -ArgumentList "doctor" `
    -WorkingDirectory $packageRoot -RedirectStandardOutput $launcherStdout `
    -RedirectStandardError $launcherStderr -WindowStyle Hidden -Wait -PassThru
if ($launcherProcess.ExitCode -ne 0) {
    $launcherError = if (Test-Path -LiteralPath $launcherStderr) {
        Get-Content -LiteralPath $launcherStderr -Raw -ErrorAction SilentlyContinue
    }
    else { "" }
    throw "Packaged start_toolbox.cmd doctor failed with exit code $($launcherProcess.ExitCode). $launcherError"
}

# Start the unpacked package with only its vendored runtime and verify a real
# loopback HTTP response. This catches launchers that pass Doctor but cannot
# import Flask while creating the web application.
$portProbe = [System.Net.Sockets.TcpListener]::new(
    [System.Net.IPAddress]::Loopback,
    0
)
$portProbe.Start()
$verifyPort = ([System.Net.IPEndPoint]$portProbe.LocalEndpoint).Port
$portProbe.Stop()
$serverStdout = Join-Path $staging "portable-server.stdout.log"
$serverStderr = Join-Path $staging "portable-server.stderr.log"
$serverSessions = Join-Path $staging "portable-server-sessions"
$serverEntrypoint = Join-Path $packageRoot "panos-toolbox.py"
$pyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
if ($pyLauncher) {
    $serverExecutable = $pyLauncher.Source
    $serverArguments = @(
        "-3", "-I", "-S", $serverEntrypoint,
        "serve", "--port", [string]$verifyPort,
        "--session-dir", $serverSessions
    )
}
else {
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $python) {
        throw "Python 3 was not found for portable HTTP verification."
    }
    $serverExecutable = $python.Source
    $serverArguments = @(
        "-I", "-S", $serverEntrypoint,
        "serve", "--port", [string]$verifyPort,
        "--session-dir", $serverSessions
    )
}
$serverProcessParameters = @{
    FilePath = $serverExecutable
    ArgumentList = $serverArguments
    WorkingDirectory = $packageRoot
    RedirectStandardOutput = $serverStdout
    RedirectStandardError = $serverStderr
    WindowStyle = "Hidden"
    PassThru = $true
}
$serverProcess = Start-Process @serverProcessParameters
$httpStatus = $null
try {
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if ($serverProcess.HasExited) {
            break
        }
        try {
            $response = Invoke-WebRequest -UseBasicParsing `
                -Uri "http://127.0.0.1:$verifyPort/api/v1/health" `
                -TimeoutSec 2
            $httpStatus = $response.StatusCode
            break
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }
}
finally {
    if (-not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force
        $serverProcess.WaitForExit()
    }
}
if ($httpStatus -ne 200) {
    $stderrText = if (Test-Path -LiteralPath $serverStderr) {
        (Get-Content -LiteralPath $serverStderr -Raw -ErrorAction SilentlyContinue)
    }
    else { "" }
    throw "Portable HTTP verification failed (status=$httpStatus). $stderrText"
}
Write-Host "Portable package HTTP verification: 127.0.0.1:$verifyPort -> 200"

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
    (Join-Path $packageRoot "start_toolbox.cmd")
    (Join-Path $packageRoot "ROZPAKUJ_I_URUCHOM.txt")
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
