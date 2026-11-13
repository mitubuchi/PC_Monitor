#Requires -RunAsAdministrator
<#
.SYNOPSIS
    キー入力 API の監視が、その場で Probe の呼び出しを拾えるかを 1 回で確かめる（設計書 §11.5）。

.DESCRIPTION
    管理者のターミナルで実行する。画面を操作しなくても済むように、次をまとめて行う。

      1. コンソール版（pcmonitor.exe）で、キー入力 API の見張りを始める
      2. 見張っている間に、PCMonitor.Probe を --key-apis で動かす
         （キーロガーが使う API を、何も取得しない形で呼ぶ。キー入力は受け取らない）
      3. 見張りが終わると、そのまま点検が走る。拾った呼び出しのすべてと、Probe の行を書き出す

    結果は artifacts\etw\monitor-run.txt に置く（git には入れない）。
    どのフォルダーから実行してもよい（場所は、このスクリプトの位置から決める）。

.EXAMPLE
    pwsh -File C:\Claude\Security\PCMonitor\tools\monitor-probe.ps1
#>
param(
    [int]$Seconds = 12
)

$ErrorActionPreference = 'Stop'

$root = Split-Path $PSScriptRoot -Parent
$outDir = Join-Path $root 'artifacts\etw'
$report = Join-Path $outDir 'monitor-run.txt'
$errors = Join-Path $outDir 'monitor-run-errors.txt'
$dataDir = Join-Path $outDir 'data'
$cli = Join-Path $root 'src\PCMonitor.Cli\bin\Debug\net9.0-windows\pcmonitor.exe'
$probe = Join-Path $root 'tests\PCMonitor.Probe\bin\Debug\net9.0-windows\PCMonitor.Probe.exe'

foreach ($file in $cli, $probe) {
    if (-not (Test-Path $file)) { throw "見つかりません。先に dotnet build PCMonitor.sln を実行してください: $file" }
}

New-Item -ItemType Directory -Force $outDir | Out-Null
Remove-Item $report, $errors -ErrorAction SilentlyContinue

Write-Host "キー入力 API を $Seconds 秒見張ります…"
# 保存先は artifacts の下にして、ふだんの「前回の結果」と許可リストには触れない
$monitor = Start-Process $cli -PassThru -WindowStyle Hidden `
    -ArgumentList '--monitor-keys', "$Seconds", '--find', 'PCMonitor.Probe', '--data-dir', "`"$dataDir`"", '--no-save' `
    -RedirectStandardOutput $report -RedirectStandardError $errors

# 見張りが始まるのを待ってから、Probe を動かす
Start-Sleep -Seconds 4
$probeProcess = Start-Process $probe -ArgumentList '--key-apis', '--seconds', '4' -PassThru
Write-Host "Probe を動かしています（PID $($probeProcess.Id)）…"
$probeProcess.WaitForExit()

Write-Host '見張りが終わるのを待っています（終わると、そのまま点検が走ります）…'
$monitor.WaitForExit()

# 追記も UTF-8、BOM 無しで（Add-Content は PowerShell の版で文字コードが変わる）
$footer = "`r`n※ Probe の PID: $($probeProcess.Id)  pcmonitor の終了コード: $($monitor.ExitCode)  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n"
[System.IO.File]::AppendAllText($report, $footer, (New-Object System.Text.UTF8Encoding $false))

Write-Host ''
Write-Host "結果を書きました: $report"
Get-Content $report -Encoding UTF8 | Where-Object { $_ -match '^\[|・|^--- |^  \d|^      |^※' } | Select-Object -First 40
