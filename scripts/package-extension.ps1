param(
  [string]$Output = "safespend-extension.zip"
)

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$extensionPath = Join-Path $root "extension"
$outputPath = Join-Path $root $Output

if (Test-Path $outputPath) {
  Remove-Item $outputPath -Force
}

$files = @(
  "manifest.json",
  "background.js",
  "content.js",
  "popup.html",
  "popup.css",
  "popup.js",
  "options.html",
  "options.css",
  "options.js"
)

Push-Location $extensionPath
try {
  Compress-Archive -Path $files -DestinationPath $outputPath -Force
  Write-Host "Extension package created at $outputPath"
} finally {
  Pop-Location
}
