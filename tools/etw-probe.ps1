#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Win32k の ETW プロバイダーから、キー入力 API の呼び出しが実際に流れてくるかを確かめる（設計書 §11.5）。

.DESCRIPTION
    管理者のターミナルで実行する。ETW のセッションを始められるのは管理者だけなので、
    Claude Code からは実行できない。

    やること:
      1. Microsoft-Windows-Win32k を、キーワード AuditApiCalls（0x400）だけで記録し始める
      2. PCMonitor.Probe を --key-apis で動かす（キーロガーが使う API を、何も取得しない形で呼ぶ）
      3. 記録を止め、流れてきたイベントを読んで、テキストにまとめる

    記録するのは API 呼び出しの監査イベントだけで、キー入力そのものは記録されない。
    結果は artifacts\etw\ に置く（git には入れない）。

.EXAMPLE
    pwsh -File tools\etw-probe.ps1
#>
param(
    [int]$Seconds = 8
)

$ErrorActionPreference = 'Stop'

$root = Split-Path $PSScriptRoot -Parent
$outDir = Join-Path $root 'artifacts\etw'
$etl = Join-Path $outDir 'win32k-audit.etl'
$report = Join-Path $outDir 'win32k-audit.txt'
$probe = Join-Path $root 'tests\PCMonitor.Probe\bin\Debug\net9.0-windows\PCMonitor.Probe.exe'
$session = 'PCMonitorEtwProbe'
$provider = '{8c416c79-d49b-4f01-a467-e56d3aa8234c}'   # Microsoft-Windows-Win32k
$keywords = '0x400'                                      # AuditApiCalls
$level = '4'                                             # Informational

if (-not (Test-Path $probe)) {
    throw "Probe が見つかりません。先に dotnet build tests\PCMonitor.Probe を実行してください: $probe"
}

New-Item -ItemType Directory -Force $outDir | Out-Null
Remove-Item $etl, $report -ErrorAction SilentlyContinue

# 画面に出たものを残す。途中で止まったとき、どこまで進んだかをあとから読めるように
# （2026-11-13 の 1 回目は、記録はできたのにまとめが書かれず、理由が分からなかった）
Start-Transcript -Path (Join-Path $outDir 'run.log') -Force | Out-Null
trap { Write-Host "止まりました: $($_.Exception.Message)（$($_.InvocationInfo.ScriptLineNumber) 行目）"; Stop-Transcript | Out-Null; break }

# 前回の実行が途中で止まっていたら、残ったセッションを片付ける
& logman stop $session -ets 2>$null | Out-Null

Write-Host "記録を始めます（$Seconds 秒）…"
& logman start $session -p $provider $keywords $level -o $etl -ets | Out-Null
if ($LASTEXITCODE -ne 0) { throw "ETW のセッションを始められませんでした（logman の終了コード $LASTEXITCODE）" }

$probePid = 0
try {
    $process = Start-Process $probe -ArgumentList '--key-apis', '--seconds', "$Seconds" -PassThru
    $probePid = $process.Id
    Write-Host "Probe を動かしています（PID $probePid）。この間に、どれかのキーを何度か押してください。"
    $process.WaitForExit()
}
finally {
    & logman stop $session -ets | Out-Null
}

Write-Host '記録を読んでいます…'
$events = @(Get-WinEvent -Path $etl -Oldest -ErrorAction SilentlyContinue)

# 記録の時点で動いていたプロセスの名前（終わったものは引けない）
$names = @{}
Get-Process | ForEach-Object { $names[[int]$_.Id] = $_.ProcessName }
$names[[int]$probePid] = 'PCMonitor.Probe'

function Format-Event($e) {
    $xml = [xml]$e.ToXml()
    $data = @($xml.Event.EventData.Data | ForEach-Object { "$($_.Name)=$($_.'#text')" })
    $who = $names[[int]$e.ProcessId]
    if (-not $who) { $who = '(終了済み)' }
    "  PID $($e.ProcessId) $who / TID $($e.ThreadId) / $($e.TimeCreated.ToString('HH:mm:ss.fff'))`n      $($data -join ', ')"
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("Win32k AuditApiCalls の実測  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$lines.Add("Windows $([Environment]::OSVersion.Version)  Probe PID $probePid  記録 $Seconds 秒  イベント総数 $($events.Count)")
$lines.Add('')
$lines.Add('--- 番号ごとの件数')
$events | Group-Object Id | Sort-Object { [int]$_.Name } | ForEach-Object { $lines.Add("  ID $($_.Name): $($_.Count) 件") }

foreach ($id in 1000, 1001, 1002, 1003) {
    $ofId = @($events | Where-Object Id -eq $id)
    $lines.Add('')
    $lines.Add("--- ID $id（$($ofId.Count) 件）")

    $fromProbe = @($ofId | Where-Object ProcessId -eq $probePid)
    $lines.Add("  Probe からのもの: $($fromProbe.Count) 件")
    $fromProbe | Select-Object -First 3 | ForEach-Object { $lines.Add((Format-Event $_)) }

    $others = @($ofId | Where-Object ProcessId -ne $probePid)
    $lines.Add("  ほかのプロセスからのもの: $($others.Count) 件")
    $others | Group-Object ProcessId | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object {
        $who = $names[[int]$_.Name]
        if (-not $who) { $who = '(終了済み)' }
        $lines.Add("    PID $($_.Name) $who : $($_.Count) 件")
    }
    $others | Select-Object -First 4 | ForEach-Object { $lines.Add((Format-Event $_)) }
}

# 書き出すファイルは UTF-8、BOM 無し
[System.IO.File]::WriteAllLines($report, $lines, (New-Object System.Text.UTF8Encoding $false))
Write-Host ''
Write-Host "まとめを書きました: $report"
Get-Content $report -Encoding UTF8 | Select-Object -First 12
Stop-Transcript | Out-Null
