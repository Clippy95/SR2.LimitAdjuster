param(
    [string]$ProjectDir
)

$ErrorActionPreference = 'Stop'

if (-not $ProjectDir) {
    $ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}

$ProjectDir = $ProjectDir.Trim().Trim('"')
$projectPath = [System.IO.Path]::GetFullPath($ProjectDir)
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $projectPath '..'))
$outputPath = Join-Path $projectPath 'BuildVersion.h'

$buildTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
$gitCount = '0'
$gitHash = 'unknown'
$gitDirty = 'false'

try {
    $safeArg = "-c"
    $safeValue = "safe.directory=$repoRoot"

    $countResult = & git $safeArg $safeValue -C $repoRoot rev-list --count HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and $countResult) {
        $gitCount = $countResult.Trim()
    }

    $hashResult = & git $safeArg $safeValue -C $repoRoot rev-parse --short HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and $hashResult) {
        $gitHash = $hashResult.Trim()
    }

    & git $safeArg $safeValue -C $repoRoot diff --no-ext-diff --quiet --exit-code 2>$null
    if ($LASTEXITCODE -eq 1) {
        $gitDirty = 'true'
    }
}
catch {
}

$header = @"
#pragma once

namespace BuildVersion
{
    inline constexpr char kBuildTimestamp[] = "$buildTimestamp";
    inline constexpr unsigned int kGitCommitCount = $gitCount;
    inline constexpr char kGitShortHash[] = "$gitHash";
    inline constexpr bool kGitDirty = $gitDirty;
}
"@

[System.IO.File]::WriteAllText($outputPath, $header, [System.Text.Encoding]::ASCII)
