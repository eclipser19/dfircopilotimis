<#
  DFIR Copilot installer for a fresh Windows machine. From the code folder:

      powershell -ExecutionPolicy Bypass -File .\install.ps1

  Finds Python 3.12 (or installs it for this user with winget), makes .venv, installs the tested
  packages (requirements-lock.txt), then asks for the rest: python -m copilot.install setup
  (Velociraptor, server.yaml, HTTPS certificate, first admin). Run it again any time: steps already
  done are skipped.
#>
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Find-Python312 {
    $tries = @(
        { py -3.12 -c "import sys; print(sys.executable)" },
        { & "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -c "import sys; print(sys.executable)" },
        { & "$env:ProgramFiles\Python312\python.exe" -c "import sys; print(sys.executable)" }
    )
    foreach ($try in $tries) {
        try {
            $path = (& $try 2>$null | Select-Object -Last 1)
            if ($LASTEXITCODE -eq 0 -and $path -and (Test-Path -LiteralPath $path.Trim())) { return $path.Trim() }
        } catch { }
    }
    return $null
}

$python = Find-Python312
if (-not $python) {
    Write-Host "Python 3.12 was not found."
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "Install Python 3.12 from python.org, then run install.ps1 again."
    }
    $answer = Read-Host "Install Python 3.12 now with winget, for this user? [Y/n]"
    if ($answer -and $answer -notmatch '^(y|yes)$') { throw "Install Python 3.12, then run install.ps1 again." }
    winget install -e --id Python.Python.3.12 --scope user --accept-package-agreements --accept-source-agreements
    $python = Find-Python312
    if (-not $python) { throw "Python 3.12 is still not found: open a new PowerShell window and run install.ps1 again." }
}
Write-Host "Python: $python"

$venvPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython)) {
    & $python -m venv (Join-Path $PSScriptRoot '.venv')
    if ($LASTEXITCODE -ne 0) { throw "Could not create .venv." }
}
Write-Host "Installing the tested packages (a few minutes the first time)..."
& $venvPython -m pip install --disable-pip-version-check -q -r requirements-lock.txt
if ($LASTEXITCODE -ne 0) { throw "pip install failed (see above)." }

& $venvPython -m copilot.install setup
exit $LASTEXITCODE
