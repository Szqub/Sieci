param(
    [switch]$SkipTests,
    [switch]$AllowDirty
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
$requirementsLock = Join-Path $toolboxRoot "backend\requirements.lock"
$legacyPackage = Join-Path $repoRoot "panorama_cleaner\panorama_cleanup"
$static = Join-Path $backendPackage "static"
$staging = Join-Path $toolboxRoot ".release-staging"
$releaseDir = Join-Path $toolboxRoot "release"

foreach ($required in @($frontend, $backendPackage, $legacyPackage)) {
    if (-not (Test-Path -LiteralPath $required -PathType Container)) {
        throw "Required directory is missing: $required"
    }
}
foreach ($requiredFile in @($requirements, $requirementsLock)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Required file is missing: $requiredFile"
    }
}

$sourceStatus = @(& git -C $repoRoot status --porcelain --untracked-files=all)
if ($LASTEXITCODE -ne 0) {
    throw "Unable to inspect the Git working tree before release."
}
if ($sourceStatus.Count -gt 0 -and -not $AllowDirty) {
    throw "Release requires a clean Git working tree. Commit changes or use -AllowDirty only for a local validation build."
}
function Invoke-BuildPython {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        $executable = $launcher.Source
        $processArguments = @("-3.12") + $Arguments
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

function Assert-ReleaseSecurity {
    param([Parameter(Mandatory = $true)][string]$PackageRoot)

    $forbiddenExtensions = @(".exe", ".dll", ".pyd", ".com", ".bat", ".vbs")
    $forbidden = @(
        Get-ChildItem -LiteralPath $PackageRoot -File -Recurse |
            Where-Object { $forbiddenExtensions -contains $_.Extension.ToLowerInvariant() }
    )
    if ($forbidden.Count -gt 0) {
        $names = ($forbidden | ForEach-Object { $_.FullName }) -join "; "
        throw "Release security gate rejected executable/script payloads: $names"
    }

    $cmdFiles = @(Get-ChildItem -LiteralPath $PackageRoot -File -Filter "*.cmd" -Recurse)
    $allowedCmd = (Join-Path $PackageRoot "start_toolbox.cmd")
    $unexpectedCmd = @($cmdFiles | Where-Object {
        -not $_.FullName.Equals($allowedCmd, [System.StringComparison]::OrdinalIgnoreCase)
    })
    if ($unexpectedCmd.Count -gt 0) {
        throw "Release security gate permits only the audited start_toolbox.cmd launcher."
    }

    $powerShellFiles = @(Get-ChildItem -LiteralPath $PackageRoot -File -Filter "*.ps1" -Recurse)
    $allowedPowerShell = (Join-Path $PackageRoot "start_toolbox.ps1")
    $unexpectedPowerShell = @($powerShellFiles | Where-Object {
        -not $_.FullName.Equals($allowedPowerShell, [System.StringComparison]::OrdinalIgnoreCase)
    })
    if ($unexpectedPowerShell.Count -gt 0) {
        throw "Release security gate permits only the audited start_toolbox.ps1 launcher."
    }

    foreach ($file in Get-ChildItem -LiteralPath $PackageRoot -File -Recurse) {
        $stream = [System.IO.File]::OpenRead($file.FullName)
        try {
            $first = $stream.ReadByte()
            $second = $stream.ReadByte()
        }
        finally {
            $stream.Dispose()
        }
        if ($first -eq 0x4D -and $second -eq 0x5A) {
            throw "Release security gate found a PE/MZ payload: $($file.FullName)"
        }
    }
}

function Write-ReleaseEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)][string]$VendorRoot,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot
    )

    $rootPrefix = $PackageRoot.TrimEnd("\") + "\"
    $manifestPath = Join-Path $PackageRoot "RELEASE-MANIFEST.json"
    $checksumPath = Join-Path $PackageRoot "SHA256SUMS.txt"
    $dependencies = @(
        Get-ChildItem -LiteralPath $VendorRoot -Directory -Filter "*.dist-info" |
            Sort-Object Name |
            ForEach-Object {
                $metadataPath = Join-Path $_.FullName "METADATA"
                $metadata = if (Test-Path -LiteralPath $metadataPath) {
                    Get-Content -LiteralPath $metadataPath -ErrorAction Stop
                }
                else { @() }
                $nameLine = $metadata | Where-Object { $_ -like "Name: *" } | Select-Object -First 1
                $versionLine = $metadata | Where-Object { $_ -like "Version: *" } | Select-Object -First 1
                [ordered]@{
                    name = if ($nameLine) { $nameLine.Substring(6).Trim() } else { $_.BaseName }
                    version = if ($versionLine) { $versionLine.Substring(9).Trim() } else { "unknown" }
                }
            }
    )
    $payloadFiles = @(
        Get-ChildItem -LiteralPath $PackageRoot -File -Recurse |
            Where-Object { $_.FullName -ne $manifestPath -and $_.FullName -ne $checksumPath } |
            Sort-Object FullName |
            ForEach-Object {
                [ordered]@{
                    path = $_.FullName.Substring($rootPrefix.Length).Replace("\", "/")
                    size = $_.Length
                    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }
    )
    $gitCommit = (& git -C $RepositoryRoot rev-parse HEAD 2>$null | Select-Object -First 1)
    $gitStatus = @(& git -C $RepositoryRoot status --porcelain --untracked-files=all 2>$null)
    $manifest = [ordered]@{
        schemaVersion = 1
        generatedAtUtc = [DateTime]::UtcNow.ToString("o")
        gitCommit = if ($gitCommit) { $gitCommit.Trim() } else { $null }
        sourceTreeDirty = $gitStatus.Count -gt 0
        securityProfile = [ordered]@{
            nativePePayloads = 0
            powershellScripts = 1
            extensionMasquerading = $false
            allowedLaunchers = @("start_toolbox.cmd", "start_toolbox.ps1")
        }
        dependencies = $dependencies
        files = $payloadFiles
    }
    [System.IO.File]::WriteAllText(
        $manifestPath,
        (($manifest | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
        [System.Text.UTF8Encoding]::new($false)
    )

    $checksumLines = @(
        Get-ChildItem -LiteralPath $PackageRoot -File -Recurse |
            Where-Object { $_.FullName -ne $checksumPath } |
            Sort-Object FullName |
            ForEach-Object {
                $relative = $_.FullName.Substring($rootPrefix.Length).Replace("\", "/")
                $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                "$hash  $relative"
            }
    )
    [System.IO.File]::WriteAllLines(
        $checksumPath,
        $checksumLines,
        [System.Text.UTF8Encoding]::new($false)
    )
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
    "--require-hashes",
    "--only-binary=:all:",
    "-r", $requirementsLock
)
# pip creates console-entrypoint launchers (for example flask.exe) even though
# Toolbox imports the libraries directly. They are unnecessary unsigned PE
# payloads and must never be shipped in the portable archive.
$vendorBin = Join-Path $packageVendorRoot "bin"
if (Test-Path -LiteralPath $vendorBin) {
    $resolvedVendorBin = (Resolve-Path -LiteralPath $vendorBin).Path
    $resolvedVendorRoot = (Resolve-Path -LiteralPath $packageVendorRoot).Path
    if (-not $resolvedVendorBin.StartsWith(
        $resolvedVendorRoot + "\",
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Refusing to remove vendor bin outside package staging: $resolvedVendorBin"
    }
    Remove-Item -LiteralPath $resolvedVendorBin -Recurse -Force
}
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
    "ROZPAKUJ_I_URUCHOM.txt",
    "LAB_VALIDATION.md",
    "start_toolbox.cmd",
    "start_toolbox.ps1"
)) {
    Copy-Item -LiteralPath (Join-Path $toolboxRoot $file) -Destination $packageRoot
}
Copy-Item -LiteralPath $requirements -Destination (Join-Path $packageRoot "backend\requirements.txt")
Copy-Item -LiteralPath $requirementsLock -Destination (Join-Path $packageRoot "backend\requirements.lock")

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

$windowsPowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) {
    throw "Windows PowerShell 5.1 was not found for launcher verification."
}
$psLauncher = Join-Path $packageRoot "start_toolbox.ps1"
$psLauncherProcess = Start-Process -FilePath $windowsPowerShell `
    -ArgumentList @("-NoLogo", "-NoProfile", "-NonInteractive", "-File", $psLauncher, "-Doctor") `
    -WorkingDirectory $packageRoot -Wait -PassThru -NoNewWindow
if ($psLauncherProcess.ExitCode -ne 0) {
    throw "Packaged start_toolbox.ps1 doctor failed with exit code $($psLauncherProcess.ExitCode)."
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
        "-3.12", "-I", "-S", $serverEntrypoint,
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
                -Uri "http://127.0.0.1:$verifyPort/" `
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
    (Join-Path $packageRoot "start_toolbox.ps1")
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

Assert-ReleaseSecurity -PackageRoot $packageRoot
Write-ReleaseEvidence `
    -PackageRoot $packageRoot `
    -VendorRoot $packageVendorRoot `
    -RepositoryRoot $repoRoot
Assert-ReleaseSecurity -PackageRoot $packageRoot

New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$archive = Join-Path $releaseDir "PanOS-Toolbox-$stamp.zip"
Compress-Archive -Path $packageRoot -DestinationPath $archive -CompressionLevel Optimal
$archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
$archiveHashPath = "$archive.sha256"
[System.IO.File]::WriteAllText(
    $archiveHashPath,
    "$archiveHash  $([System.IO.Path]::GetFileName($archive))$([Environment]::NewLine)",
    [System.Text.UTF8Encoding]::new($false)
)

$resolvedStaging = (Resolve-Path -LiteralPath $staging).Path
if (-not $resolvedStaging.StartsWith($toolboxRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean a directory outside PanOS-Toolbox: $resolvedStaging"
}
Remove-Item -LiteralPath $resolvedStaging -Recurse -Force

Write-Host "Release package ready: $archive"
Write-Host "Release checksum ready: $archiveHashPath"
