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

    $env:IMAGE = "ghcr.io/fifstorm4/crossdraft:0.1.0"
    .\run.ps1 env present
#>

$ErrorActionPreference = "Stop"
$image = if ($env:IMAGE) { $env:IMAGE } else { "crossdraft" }

# Windows marks a downloaded file so PowerShell refuses to run it, and the
# refusal talks about digital signatures rather than about where the file
# came from. Clearing the mark on this one file is enough; extracting from
# the tarball also avoids it, which is why the same script sometimes runs
# and sometimes does not.
try { Unblock-File -Path $PSCommandPath -ErrorAction SilentlyContinue } catch {}

# `docker image inspect` writes to stderr when the image is absent, and with
# ErrorActionPreference set to Stop PowerShell treats a native command's
# stderr as terminating -- so the "is it built yet?" check kills the script
# precisely when the answer is no. `docker images -q` reports absence as an
# empty string on stdout instead, which is a question rather than a failure.
$exists = docker images -q $image 2>$null

if (-not $exists) {
    # A published image is a two-minute pull; building locally is twenty to
    # forty, most of it fetching SageMath. Try the registry first and fall
    # back to building, so a fresh machine does not pay for a build nobody
    # needed.
    if ($image -like "ghcr.io/*") {
        Write-Host "pulling $image" -ForegroundColor Yellow
        docker pull $image
        if ($LASTEXITCODE -eq 0) { $exists = docker images -q $image 2>$null }
    }
}

if (-not $exists) {
    Write-Host "building $image (once; SageMath makes this slow, allow 20-40 min)" -ForegroundColor Yellow
    docker build -t $image $PSScriptRoot
    if ($LASTEXITCODE -ne 0) { throw "build failed" }
} elseif ($image -notlike "ghcr.io/*") {
    # The container runs the image's copy of the code, not the checkout's.
    # Unpacking a new tarball therefore changes nothing until the image is
    # rebuilt, and the symptom is the CLI rejecting a command it should have
    # -- which reads like a broken download rather than a stale image.
    $built = docker inspect -f '{{.Created}}' $image 2>$null
    if ($built) {
        $imageTime = [datetime]::Parse($built).ToUniversalTime()
        # -Include only applies when -Path carries a wildcard, so filter
        # afterwards; matching nothing would disable the check silently.
        $newest = Get-ChildItem -Path $PSScriptRoot -Recurse -File `
                -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.py', '.java' -or
                           $_.Name -in 'Dockerfile', 'Makefile' } |
            Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
        if ($newest -and $newest.LastWriteTimeUtc -gt $imageTime) {
            Write-Host "source is newer than the image ($($newest.Name) changed after it was built)" -ForegroundColor Yellow
            Write-Host "rebuilding; cached layers make this quick" -ForegroundColor DarkGray
            docker build -t $image $PSScriptRoot
            if ($LASTEXITCODE -ne 0) { throw "build failed" }
        }
    }
}

# The GUI needs its port published, and a different entrypoint. Everything
# else is a one-shot command that writes to the mounted directory and exits.
if ($args.Count -gt 0 -and $args[0] -eq "gui") {
    $port = if ($env:DIGGUI_PORT) { $env:DIGGUI_PORT } else { "8765" }

    # A GUI container left running from a previous session still holds the
    # port, and Docker reports that as "port is already allocated" without
    # saying what holds it.
    #
    # Filter on the published port, not on the image. Rebuilding moves the
    # `crossdraft` tag to a new image id while the running container still
    # descends from the old one, so an ancestor filter stops matching exactly
    # when it is needed -- and returns nothing, which then makes `docker stop`
    # complain about missing arguments instead.
    $stale = @(docker ps -q --filter "publish=$port")
    if ($stale.Count -gt 0) {
        Write-Host "stopping a container already holding port $port" -ForegroundColor DarkGray
        docker stop @stale | Out-Null
    }

    Write-Host "CrossDraft GUI: open http://127.0.0.1:$port" -ForegroundColor Green
    Write-Host "ctrl-c to stop" -ForegroundColor DarkGray
    # Publish on loopback only. The server binds 0.0.0.0 because inside a
    # container that is the only address the port forward can reach, but the
    # forward itself has no reason to accept from the network.
    docker run --rm -it -p "127.0.0.1:${port}:${port}" -e "DIGGUI_PORT=$port" `
        -v "${PWD}:/work" --entrypoint python3 $image `
        /opt/crossdraft/python/diggui.py
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "If that said 'port is already allocated', something else " -NoNewline
        Write-Host "is on port $port." -ForegroundColor Yellow
        Write-Host "  docker ps                        # see what is running"
        Write-Host "  `$env:DIGGUI_PORT = '8766'        # or just use another port"
        Write-Host "  .\run.ps1 gui"
    }
    exit $LASTEXITCODE
}

# No -u here: Windows has no POSIX uid, and Docker Desktop maps ownership
# on bind mounts by itself.
docker run --rm -it -v "${PWD}:/work" $image @args
