# Builds the web page into bin\site: the reader compiled to WebAssembly,
# Go's loader for it, the page itself, the icon and the examples.
#
#   .\scripts\build-site.ps1
#
# Open bin\site through a web server to try it, because browsers do not
# load WebAssembly from a file:// address:
#
#   python -m http.server 8000 --bind 127.0.0.1 --directory bin\site

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'bin\site'
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force $out | Out-Null

Push-Location $root
try {
  $env:GOOS, $env:GOARCH, $env:CGO_ENABLED = 'js', 'wasm', '0'
  go build -trimpath -ldflags '-s -w -buildid=' -o (Join-Path $out 'lookfirst.wasm') ./cmd/wasm
  if ($LASTEXITCODE) { throw 'building the WebAssembly reader failed' }
} finally {
  Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
  Pop-Location
}

$goroot = (go env GOROOT).Trim()
Copy-Item (Join-Path $goroot 'lib\wasm\wasm_exec.js') $out
Copy-Item (Join-Path $root 'site\*') $out
Copy-Item (Join-Path $root 'vscode\media\icon.svg') $out

# The examples, in the order and with the titles the page shows. Bicep is
# left out: it needs Microsoft's compiler, which a browser does not have.
$titles = [ordered]@{
  'python-helper'    = 'A "handy" Python helper'
  'setup-scripts'    = 'Server setup scripts'
  'azure-vm'         = 'Azure Linux VM'
  'azure-webapp-sql' = 'Azure web app with SQL'
  'aws-ec2'          = 'AWS server, database and bucket'
  'compose'          = 'docker-compose app'
  'kubernetes'       = 'Kubernetes deployment'
  'node-api'         = 'Node.js API'
  'packages'         = 'package.json and requirements.txt'
}
$examples = foreach ($dir in $titles.Keys) {
  $files = Get-ChildItem (Join-Path $root "examples\$dir") -File | ForEach-Object {
    [ordered]@{ name = "$dir/$($_.Name)"; text = [IO.File]::ReadAllText($_.FullName) }
  }
  [ordered]@{ title = $titles[$dir]; files = @($files) }
}
$json = ConvertTo-Json -InputObject @($examples) -Depth 5 -Compress
Set-Content (Join-Path $out 'examples.js') "window.LOOKFIRST_EXAMPLES = $json;" -Encoding utf8NoBOM

# Stamp every file reference with a hash of what was built, such as
# app.js?v=3f9a1c2b. Browsers keep files for a while; a new stamp makes
# them fetch the new version at once instead of mixing old and new files.
$sha = [Security.Cryptography.SHA256]::Create()
$parts = Get-ChildItem $out -File | Sort-Object Name | ForEach-Object { [IO.File]::ReadAllBytes($_.FullName) }
$all = [byte[]]($parts | ForEach-Object { $_ })
$build = ([BitConverter]::ToString($sha.ComputeHash($all)) -replace '-', '').Substring(0, 12).ToLower()
foreach ($name in 'index.html', 'app.js') {
  $path = Join-Path $out $name
  $text = [IO.File]::ReadAllText($path) -replace '__BUILD__', $build
  [IO.File]::WriteAllText($path, $text)
}
"build $build"

Get-ChildItem $out | ForEach-Object { '{0,10:N0}  {1}' -f $_.Length, $_.Name }
