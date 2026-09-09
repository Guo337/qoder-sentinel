$ErrorActionPreference = "Continue"
# Optional proxy for restricted networks, e.g. $env:HTTPS_PROXY = "http://host:port"
$proxy = $env:HTTPS_PROXY
$iwr = @{ TimeoutSec = 30; UseBasicParsing = $true }
if ($proxy) { $iwr.Proxy = $proxy }
$base = "https://raw.githubusercontent.com/OpenHands/software-agent-sdk/main/openhands-sdk/openhands/sdk/security"
$out = Join-Path (Split-Path $PSScriptRoot -Parent) "reference\openhands"
New-Item -ItemType Directory -Force -Path $out | Out-Null

$files = @(
  "__init__.py",
  "risk.py",
  "confirmation_policy.py",
  "analyzer.py",
  "shell_parser.py",
  "_shell_ast.py",
  "llm_analyzer.py",
  "ensemble.py"
)

$utf8 = New-Object System.Text.UTF8Encoding($false)
foreach ($f in $files) {
  try {
    $r = Invoke-WebRequest -Uri "$base/$f" @iwr
    [System.IO.File]::WriteAllText((Join-Path $out $f), $r.Content, $utf8)
    Write-Output ("OK   " + $f + "  " + $r.Content.Length)
  } catch {
    Write-Output ("FAIL " + $f + " : " + $_.Exception.Message)
  }
}

# LICENSE at repo root
try {
  $lic = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/OpenHands/software-agent-sdk/main/LICENSE" @iwr
  [System.IO.File]::WriteAllText((Join-Path (Split-Path $PSScriptRoot -Parent) "reference\LICENSE-OpenHands-software-agent-sdk.txt"), $lic.Content, $utf8)
  Write-Output ("OK   LICENSE  " + $lic.Content.Length)
} catch {
  Write-Output ("FAIL LICENSE : " + $_.Exception.Message)
}
