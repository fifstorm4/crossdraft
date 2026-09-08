<#
.SYNOPSIS
  Run CrossDraft in Docker against the current directory.

.EXAMPLE
  .\run.ps1 selftest
  .\run.ps1 build present
  .\run.ps1 analyse present --rounds 3 --export fig.svg

.NOTES
  Files land in the directory you ran this from, not inside the container.
  Pin a release with the IMAGE environment variable:

    $env:IMAGE = "ghcr.io/fifstorm/crossdraft:0.1.0"
    .\run.ps1 env present
#>

$ErrorActionPreference = "Stop"
$image = if ($env:IMAGE) { $env:IMAGE } else { "crossdraft" }

docker image inspect $image *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "building $image (once; SageMath makes this slow, allow 20-40 min)" -ForegroundColor Yellow
    docker build -t $image $PSScriptRoot
    if ($LASTEXITCODE -ne 0) { throw "build failed" }
}

# No -u here: Windows has no POSIX uid, and Docker Desktop maps ownership
# on bind mounts by itself.
docker run --rm -it -v "${PWD}:/work" $image @args
