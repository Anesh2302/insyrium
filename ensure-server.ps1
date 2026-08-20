# ensure-server.ps1 — keep the Insyrium portal running.
# Idempotent: exits immediately if something is already listening on the port.
$ErrorActionPreference = 'SilentlyContinue'
$dir = 'D:\simonpeter\insyrium'
$port = 5000
$lock = Join-Path $dir 'server.pid'

# Already listening?
if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
    exit 0
}

# Stale lock guard: if the PID file points at a live python, nothing to do.
if (Test-Path $lock) {
    $serverPid = Get-Content $lock | Select-Object -First 1
    $proc = Get-Process -Id $serverPid -ErrorAction SilentlyContinue
    if ($proc -and $proc.ProcessName -match 'python') { exit 0 }
    Remove-Item $lock -Force
}

# Start the server.
$p = Start-Process -FilePath 'python' -ArgumentList 'app.py' `
    -WorkingDirectory $dir `
    -RedirectStandardOutput (Join-Path $dir 'server.out.log') `
    -RedirectStandardError (Join-Path $dir 'server.err.log') `
    -WindowStyle Hidden -PassThru

Start-Sleep -Seconds 6
if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
    Set-Content -Path $lock -Value $p.Id
    exit 0
}

Add-Content -Path (Join-Path $dir 'server-restarts.log') `
    -Value "$(Get-Date -Format s)  start failed (pid $($p.Id))"
exit 1
