# Установка общей памяти WorkHack на Windows (PowerShell). НЕ проверялось на реальной Windows, проверь doctor.
#   .\install.ps1 [-Project "C:\путь\к\workhack"]
param([string]$Project = "")
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $MyInvocation.MyCommand.Path
$Wh = Join-Path $Repo "bin\wh.cmd"

Write-Host "== 1/5 Python"
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { Write-Host "Нужен Python 3.9+: winget install Python.Python.3.12"; exit 2 }

Write-Host "== 2/5 wh в PATH пользователя"
$binDir = Join-Path $Repo "bin"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$binDir*") {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$binDir", "User")
  Write-Host "Добавил $binDir в PATH. Открой новое окно терминала."
}

Write-Host "== 3/5 Данные R2"
$home_ = if ($env:WH_HOME) { $env:WH_HOME } else { Join-Path $env:USERPROFILE ".workhack" }
if ((Test-Path "$home_\config.json") -and (Test-Path "$home_\credentials")) { Write-Host "уже настроено" }
elseif ($env:WH_SETUP_BUCKET) { & $Wh setup --from-env }
else { & $Wh setup }

Write-Host "== 4/5 Проверка доступа"
& $Wh doctor
if ($LASTEXITCODE -ne 0) { Write-Host "doctor не прошёл: см. INSTALL.md"; exit 11 }

Write-Host "== 5/5 Контекст и проект"
$existing = & $Wh ls "context/"
if (-not $existing) { & $Wh push-context (Join-Path $Repo "seed\context") }
if ($Project) { & $Wh init-project $Project }
if (Get-Command claude -ErrorAction SilentlyContinue) {
  claude plugin marketplace add $Repo
  claude plugin install workhack-context@workhack-context-storage
}
Write-Host "ГОТОВО. Дальше: docs\USAGE.md"
