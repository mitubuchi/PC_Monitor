#Requires -RunAsAdministrator
<#
.SYNOPSIS
    キー入力 API の監視が、その場で Probe の呼び出しを拾えるかを 1 回で確かめる（設計書 §11.5）。

.DESCRIPTION
    管理者のターミナルで実行する。画面を操作しなくても済むように、次をまとめて行う。

      1. コンソール版（pcmonitor-cli.exe）で、キー入力 API の見張りを始める
      2. 見張っている間に、PCMonitor.Probe を --key-apis で動かす
         （キーロガーが使う API を、何も取得しない形で呼ぶ。キー入力は受け取らない）
      3. 見張りが終わると、そのまま点検が走る。拾った呼び出しのすべてと、Probe の行を書き出す

    結果は artifacts\etw\monitor-run.txt に置く（git には入れない）。
    どのフォルダーから実行してもよい（場所は、このスクリプトの位置から決める）。

.EXAMPLE
    pwsh -File C:\Claude\Security\PCMonitor\tools\monitor-probe.ps1
#>
param(
    [int]$Seconds = 12,

    # Probe を動かさず、ふだんの状態を見張るだけにする。正規のソフトがどれだけ呼んでいるかを知るため。
    # 見張っている間は、PC をふだんどおりに使う（スタート メニューを開く、アプリを切り替える、など）
    #   pwsh -File tools\monitor-probe.ps1 -Ambient -Seconds 120
    [switch]$Ambient
)

$ErrorActionPreference = 'Stop'

$root = Split-Path $PSScriptRoot -Parent
$outDir = Join-Path $root 'artifacts\etw'
$name = if ($Ambient) { 'monitor-ambient' } else { 'monitor-run' }
$report = Join-Path $outDir "$name.txt"
$errors = Join-Path $outDir "$name-errors.txt"
$dataDir = Join-Path $outDir 'data'
$cli = Join-Path $root 'src\PCMonitor.Cli\bin\Debug\net9.0-windows\pcmonitor-cli.exe'
$probe = Join-Path $root 'tests\PCMonitor.Probe\bin\Debug\net9.0-windows\PCMonitor.Probe.exe'

foreach ($file in $cli, $probe) {
    if (-not (Test-Path $file)) { throw "見つかりません。先に dotnet build PCMonitor.sln を実行してください: $file" }
}

New-Item -ItemType Directory -Force $outDir | Out-Null
Remove-Item $report, $errors -ErrorAction SilentlyContinue

Write-Host "キー入力 API を $Seconds 秒見張ります…"
# 保存先は artifacts の下にして、ふだんの「前回の結果」と許可リストには触れない
# ふだんの状態を見るときは、候補になったもの（中 以上）を出す。Probe を確かめるときは、Probe の行だけを出す
$show = if ($Ambient) { @('--min-level', 'medium', '--verbose') } else { @('--find', 'PCMonitor.Probe') }
$monitor = Start-Process $cli -PassThru -WindowStyle Hidden `
    -ArgumentList (@('--monitor-keys', "$Seconds") + $show + @('--data-dir', "`"$dataDir`"", '--no-save')) `
    -RedirectStandardOutput $report -RedirectStandardError $errors

$probeNote = 'Probe は動かしていない（ふだんの状態を見張った）'
if ($Ambient) {
    Write-Host 'PC をふだんどおりに使ってください（スタート メニューを開く、アプリを切り替える、など）。'
}
else {
    # 見張りが始まるのを待ってから、Probe を動かす
    Start-Sleep -Seconds 4
    $probeProcess = Start-Process $probe -ArgumentList '--key-apis', '--seconds', '4' -PassThru
    Write-Host "Probe を動かしています（PID $($probeProcess.Id)）…"
    $probeProcess.WaitForExit()
    $probeNote = "Probe の PID: $($probeProcess.Id)"
}

Write-Host '見張りが終わるのを待っています（終わると、そのまま点検が走ります）…'
$monitor.WaitForExit()

# 追記も UTF-8、BOM 無しで（Add-Content は PowerShell の版で文字コードが変わる）
$footer = "`r`n※ $probeNote  pcmonitor の終了コード: $($monitor.ExitCode)  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n"
[System.IO.File]::AppendAllText($report, $footer, (New-Object System.Text.UTF8Encoding $false))

Write-Host ''
Write-Host "結果を書きました: $report"
Get-Content $report -Encoding UTF8 | Where-Object { $_ -match '^\[|・|^--- |^  \d|^      |^※' } | Select-Object -First 40
