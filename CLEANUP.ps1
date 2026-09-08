<#
.SYNOPSIS
  Remove stray copies and fix line endings, once.

.DESCRIPTION
  Extracting the tarball inside the repository leaves a nested copy of the
  whole tree; extracting individually-presented files there leaves loose
  copies at the root: a second ci.yml beside the real one under
  .github/workflows, a second test_gui.py beside tests/. They are dead copies
  that drift out of step with the originals, and a stray ci.yml at the root
  does nothing at all -- GitHub only reads .github/workflows.

  Also renormalises line endings against .gitattributes. Git rewrites LF as
  CRLF on checkout under Windows, and java/Makefile stops working when it
  does: make hands the stray carriage return to the shell, which then reports
  a command nobody typed.

.EXAMPLE
  .\CLEANUP.ps1
#>

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# Root-level duplicates of files that live in a subdirectory.
$strays = @(
    "ci.yml", "test_gui.py", "digcli.py", "digbuild.py", "digparts.py",
    "dig2claasp.py", "digtrail.py", "digcost.py", "digattack.py",
    "digstat.py", "diggui.py", "doctor.py", "provenance.py", "ciphers.py",
    "check_deps.py", "preload.py", "setup_sage.py", "setup_nist.py",
    "patch_claasp.py", "test_all.py", "test_fuzz.py", "test_features.py",
    "test_analysis.py", "test_statistical.py", "test_present_reference.py",
    "llbc_round.py", "llbc_loop.py", "llbc_table6.csv", "Makefile"
)

# A whole second copy of the tree, from extracting the tarball into the
# repository rather than over it. Git tracks it, CI ignores it -- GitHub only
# reads .github/workflows at the root -- so it drifts silently out of date
# and anyone browsing the repository finds two versions of every file.
if (Test-Path "crossdraft" -PathType Container) {
    Write-Host "  removing a nested copy of the whole tree (crossdraft/)" -ForegroundColor Yellow
    git rm -r --cached -q crossdraft 2>$null | Out-Null
    Remove-Item -Recurse -Force crossdraft
}

$removed = 0
foreach ($f in $strays) {
    if (Test-Path $f -PathType Leaf) {
        Write-Host "  removing stray $f" -ForegroundColor DarkGray
        git rm --cached -q $f 2>$null | Out-Null
        Remove-Item $f -Force
        $removed++
    }
}
if ($removed -eq 0) { Write-Host "  no strays at the root" }

if (-not (Test-Path ".gitattributes")) {
    throw ".gitattributes is missing; extract the current tarball first"
}

Write-Host "  renormalising line endings" -ForegroundColor DarkGray
git add --renormalize .
git add -A

Write-Host ""
Write-Host "Ready. Review and commit:" -ForegroundColor Green
Write-Host "  git status --short"
Write-Host "  git commit -m 'Normalise line endings, drop stray root copies'"
Write-Host "  git push"
