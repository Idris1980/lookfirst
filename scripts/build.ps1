# Builds the lookfirst program for every platform the VS Code extension
# supports and puts the binaries in vscode\bin. With -Package, it also makes
# one .vsix per platform with vsce.
#
#   .\scripts\build.ps1
#   .\scripts\build.ps1 -Package

param([switch]$Package)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root 'vscode\bin'
New-Item -ItemType Directory -Force $bin | Out-Null

# VS Code platform name -> Go GOOS/GOARCH
$targets = [ordered]@{
  'win32-x64'    = @('windows', 'amd64')
  'win32-arm64'  = @('windows', 'arm64')
  'darwin-x64'   = @('darwin', 'amd64')
  'darwin-arm64' = @('darwin', 'arm64')
  'linux-x64'    = @('linux', 'amd64')
  'linux-arm64'  = @('linux', 'arm64')
}

Push-Location $root
try {
  go vet ./...
  if ($LASTEXITCODE) { throw 'go vet failed' }
  foreach ($t in $targets.GetEnumerator()) {
    $env:GOOS, $env:GOARCH = $t.Value
    $env:CGO_ENABLED = '0'
    $exe = if ($t.Value[0] -eq 'windows') { '.exe' } else { '' }
    $out = Join-Path $bin "lookfirst-$($t.Key)$exe"
    # -trimpath and no build ID make the same source give the same file.
    go build -trimpath -ldflags '-s -w -buildid=' -o $out ./cmd/lookfirst
    if ($LASTEXITCODE) { throw "build failed for $($t.Key)" }
    Write-Host "built $out"
  }
} finally {
  Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
  Pop-Location
}

$sums = Get-ChildItem $bin -Filter 'lookfirst-*' | ForEach-Object {
  '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
}
Set-Content (Join-Path $bin 'SHA256SUMS.txt') $sums

if ($Package) {
  Push-Location (Join-Path $root 'vscode')
  try {
    foreach ($t in $targets.Keys) {
      # Each package carries only its own platform's binary.
      $keep = Get-ChildItem bin -Filter "lookfirst-$t*" | Select-Object -ExpandProperty Name
      $ignore = Get-Content .vscodeignore
      $extra = Get-ChildItem bin -Filter 'lookfirst-*' | Where-Object { $_.Name -notin $keep } | ForEach-Object { "bin/$($_.Name)" }
      Set-Content .vscodeignore ($ignore + $extra)
      try {
        npx --yes @vscode/vsce@3.6.0 package --target $t
        if ($LASTEXITCODE) { throw "packaging failed for $t" }
      } finally {
        Set-Content .vscodeignore $ignore
      }
    }
  } finally {
    Pop-Location
  }
}
