<#
  Starts Velociraptor, every image's dead-disk client and the web app (python -m copilot.install start).
  Ctrl+C stops everything. Add images with:  .\.venv\Scripts\python.exe -m copilot.install add-image <path>
#>
Set-Location -LiteralPath $PSScriptRoot
& (Join-Path $PSScriptRoot '.venv\Scripts\python.exe') -m copilot.install start
exit $LASTEXITCODE
