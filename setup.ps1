# Wrapper de setup (Windows). Delega para install.py. Requer python no PATH.
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { $py = (Get-Command py -ErrorAction SilentlyContinue).Source }
if (-not $py) { Write-Error "python nao encontrado no PATH"; exit 1 }
& $py "$PSScriptRoot\install.py" @args
