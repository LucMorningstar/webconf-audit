Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$repoSrc = Join-Path $repoRoot "src"
$datasetRoot = Join-Path $repoRoot "demo\real_world_configs"
$metadataPath = Join-Path $datasetRoot "metadata.json"
$reportsDir = Join-Path $datasetRoot "reports"

function Resolve-PythonExecutable {
    $candidates = @()

    if ($env:WEBCONF_AUDIT_PYTHON) {
        $configured = $env:WEBCONF_AUDIT_PYTHON.Trim()
        if ([string]::IsNullOrWhiteSpace($configured)) {
            throw "WEBCONF_AUDIT_PYTHON is set but empty."
        }

        $configuredCommand = Get-Command $configured -ErrorAction SilentlyContinue
        if ($configuredCommand) {
            return $configuredCommand.Source
        }

        if (Test-Path $configured -PathType Leaf) {
            return (Resolve-Path $configured).Path
        }

        throw "WEBCONF_AUDIT_PYTHON is set but cannot be resolved: $configured"
    }

    if ($env:VIRTUAL_ENV) {
        $candidates += @(
            (Join-Path $env:VIRTUAL_ENV "Scripts\python.exe")
            (Join-Path $env:VIRTUAL_ENV "bin/python")
        )
    }

    $candidates += @(
        (Join-Path $repoRoot ".venv\Scripts\python.exe")
        (Join-Path $repoRoot ".venv/bin/python")
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate -PathType Leaf)) {
            return (Resolve-Path $candidate).Path
        }
    }

    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCommand) {
        return $pythonCommand.Source
    }

    throw "Python interpreter not found. Set WEBCONF_AUDIT_PYTHON or create .venv."
}

function ConvertTo-ProcessArgument {
    param([string]$Argument)

    if ($null -eq $Argument -or $Argument.Length -eq 0) {
        return '""'
    }

    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    $escaped = $Argument -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

function Invoke-SampleCommand {
    param([string[]]$Command)

    $stdoutPath = [System.IO.Path]::GetTempFileName()
    $stderrPath = [System.IO.Path]::GetTempFileName()
    try {
        $argumentList = @()
        if ($Command.Length -gt 1) {
            $argumentList = $Command[1..($Command.Length - 1)] | ForEach-Object {
                ConvertTo-ProcessArgument $_
            }
        }

        $process = Start-Process `
            -FilePath $Command[0] `
            -ArgumentList ($argumentList -join ' ') `
            -WorkingDirectory $repoRoot `
            -Wait `
            -PassThru `
            -NoNewWindow `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath

        $stdout = [System.IO.File]::ReadAllText($stdoutPath)
        $stderr = [System.IO.File]::ReadAllText($stderrPath)

        return @{
            ExitCode = $process.ExitCode
            Stdout = $stdout
            Stderr = $stderr
        }
    }
    finally {
        if (Test-Path $stdoutPath) {
            Remove-Item $stdoutPath -Force
        }
        if (Test-Path $stderrPath) {
            Remove-Item $stderrPath -Force
        }
    }
}

function Save-Utf8NoBom {
    param(
        [string]$Path,
        [string]$Content
    )

    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}

function Resolve-DatasetFile {
    param([string]$RelativePath)

    $resolvedDatasetRoot = (Resolve-Path -LiteralPath $datasetRoot).ProviderPath
    $combinedPath = Join-Path $datasetRoot $RelativePath

    if (-not (Test-Path -LiteralPath $combinedPath -PathType Leaf)) {
        throw "Dataset file does not exist: $RelativePath"
    }

    $resolvedPath = (Resolve-Path -LiteralPath $combinedPath).ProviderPath
    $datasetPrefix = $resolvedDatasetRoot.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    ) + [IO.Path]::DirectorySeparatorChar

    if (
        $resolvedPath -ne $resolvedDatasetRoot -and
        -not $resolvedPath.StartsWith($datasetPrefix, [StringComparison]::OrdinalIgnoreCase)
    ) {
        throw "Dataset file escapes real-world fixture root: $RelativePath"
    }

    return $resolvedPath
}

function Resolve-SafeSampleId {
    param([object]$Value)

    $sampleId = [string]$Value
    if ([string]::IsNullOrWhiteSpace($sampleId)) {
        throw "Sample id must not be empty."
    }

    if ($sampleId.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
        throw "Sample id contains characters that are unsafe for report filenames: $sampleId"
    }

    return $sampleId
}

function Get-AnalyzerArgumentList {
    param(
        [pscustomobject]$Sample,
        [string]$ConfigPath,
        [switch]$Json
    )

    $analyzerArgs = @(
        "-m",
        "webconf_audit.cli",
        "analyze-$($Sample.server_type)",
        $ConfigPath
    )

    if ($Sample.server_type -eq "iis") {
        $analyzerArgs += "--no-tls-registry"
    }

    if ($Sample.PSObject.Properties.Name -contains "analyzer_options") {
        $options = $Sample.analyzer_options
        if ($Sample.server_type -eq "lighttpd" -and $null -ne $options -and ($options.PSObject.Properties.Name -contains "host")) {
            $analyzerArgs += @("--host", $options.host)
        }
        if ($Sample.server_type -eq "iis" -and $null -ne $options -and ($options.PSObject.Properties.Name -contains "machine_config")) {
            $machineConfig = Resolve-DatasetFile $options.machine_config
            $analyzerArgs += @("--machine-config", $machineConfig)
        }
    }

    if ($Json) {
        $analyzerArgs += @("--format", "json")
    }

    return $analyzerArgs
}

$pythonExe = Resolve-PythonExecutable

if (Test-Path $repoSrc) {
    if ([string]::IsNullOrEmpty($env:PYTHONPATH)) {
        $env:PYTHONPATH = $repoSrc
    }
    elseif (-not (($env:PYTHONPATH -split [IO.Path]::PathSeparator) -contains $repoSrc)) {
        $env:PYTHONPATH = "$repoSrc$([IO.Path]::PathSeparator)$env:PYTHONPATH"
    }
}

New-Item -ItemType Directory -Force -Path $reportsDir | Out-Null

$metadata = Get-Content -Path $metadataPath -Raw | ConvertFrom-Json
if ($null -eq $metadata.samples -or $metadata.samples.Count -eq 0) {
    Write-Error "No samples found in metadata file: $metadataPath"
    exit 1
}

$failedSamples = @()

foreach ($sample in $metadata.samples) {
    $configPath = Resolve-DatasetFile $sample.entrypoint
    $sampleId = Resolve-SafeSampleId $sample.id
    Write-Output "== $sampleId =="

    $textCommand = @($pythonExe) + (Get-AnalyzerArgumentList -Sample $sample -ConfigPath $configPath)
    $textResult = Invoke-SampleCommand -Command $textCommand
    $textReportPath = Join-Path $reportsDir "$sampleId.txt"
    Save-Utf8NoBom $textReportPath (($textResult.Stdout + $textResult.Stderr).TrimEnd())

    if ($textResult.ExitCode -ne 0) {
        Write-Warning "$sampleId text report failed with exit code $($textResult.ExitCode)"
        $failedSamples += "${sampleId}:text"
    }

    $jsonCommand = @($pythonExe) + (Get-AnalyzerArgumentList -Sample $sample -ConfigPath $configPath -Json)
    $jsonResult = Invoke-SampleCommand -Command $jsonCommand
    $jsonReportPath = Join-Path $reportsDir "$sampleId.json"
    Save-Utf8NoBom $jsonReportPath $jsonResult.Stdout

    if ($jsonResult.ExitCode -ne 0) {
        Write-Warning "$sampleId JSON report failed with exit code $($jsonResult.ExitCode)"
        $failedSamples += "${sampleId}:json"
    }
}

Write-Output ""
Write-Output "Reports saved under: $reportsDir"

if ($failedSamples.Count -gt 0) {
    Write-Warning "Failed sample runs: $($failedSamples -join ', ')"
    exit 1
}

Write-Output "All real-world-like config samples were analyzed successfully."
