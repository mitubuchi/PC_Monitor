<#
.SYNOPSIS
    ほかの Windows PC に渡すための ZIP を作る。

.DESCRIPTION
    画面（PCMonitor.exe）とコンソール版（pcmonitor-cli.exe）を、.NET 10 の実行環境ごと
    1 つのフォルダーにまとめて（自己完結型）、ZIP にする。受け取った PC に .NET は要らない。

    同梱する実行環境は、ZIP を作ったときの SDK に入っている版になる。セキュリティ修正が出たら、
    SDK を新しくしてから作り直すこと。

    同梱しないもの:
      - PCMonitor.Probe（検知を確かめるための検証プログラム）。キーロガーが使う API を呼ぶので、
        ウイルス対策ソフトに止められうるうえ、使う人には要らない
      - tools\ のスクリプト（開発者向け）
      - デバッグ用のシンボル（.pdb）

    結果は artifacts\publish\ に置く（git には入れない）。
      PCMonitor-<版>-<実行環境>\        展開した状態のフォルダー
      PCMonitor-<版>-<実行環境>.zip
      PCMonitor-<版>-<実行環境>.zip.sha256.txt

    版は Directory.Build.props の <Version> から取る。

.EXAMPLE
    pwsh -File tools\publish.ps1
#>
param(
    # 確かめたのは win-x64 だけ。win-arm64 も作れるが、動作は確かめていない
    [ValidateSet('win-x64', 'win-arm64')]
    [string]$Runtime = 'win-x64'
)

$ErrorActionPreference = 'Stop'

# .NET 10 の SDK を探す。PATH の dotnet に無ければ、ユーザーのフォルダーに入れたものを使う
# （管理者権限なしで入れるときの置き場所。~/ClaudeDev/rules/windows.md「winget install は…終わらない」）
function Find-Dotnet10 {
    $candidates = @()
    $command = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($command) { $candidates += $command.Source }
    $candidates += (Join-Path $env:LOCALAPPDATA 'Programs\dotnet10\dotnet.exe')
    foreach ($candidate in $candidates) {
        if (-not (Test-Path $candidate)) { continue }
        if (@(& $candidate --list-sdks 2>$null) -match '^10\.') { return $candidate }
    }
    throw '.NET 10 の SDK が見つかりません。https://dotnet.microsoft.com/download/dotnet/10.0 から入れてください'
}
$dotnet = Find-Dotnet10

$root = Split-Path $PSScriptRoot -Parent
[xml]$props = Get-Content (Join-Path $root 'Directory.Build.props') -Raw
$version = @($props.Project.PropertyGroup.Version | Where-Object { $_ })[0]
if (-not $version) { throw 'Directory.Build.props に <Version> がありません' }

$name = "PCMonitor-$version-$Runtime"
$publishRoot = Join-Path $root 'artifacts\publish'
$out = Join-Path $publishRoot $name
$zip = "$out.zip"
$hashFile = "$zip.sha256.txt"

New-Item -ItemType Directory -Force $publishRoot | Out-Null
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
Remove-Item $zip, $hashFile -ErrorAction SilentlyContinue

# コンソール版を先に、画面を後に出す。同じ実行環境のファイルは同じものなので、上書きされても困らない
$projects = @(
    'src\PCMonitor.Cli\PCMonitor.Cli.csproj',
    'src\PCMonitor.Wpf\PCMonitor.Wpf.csproj'
)
foreach ($project in $projects) {
    Write-Host "発行しています: $project"
    & $dotnet publish (Join-Path $root $project) `
        -c Release -r $Runtime --self-contained true -o $out `
        -p:DebugType=none -p:DebugSymbols=false --nologo -v q
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish が失敗しました（$project、終了コード $LASTEXITCODE）" }
}

# TraceEvent は、全部の CPU 向けの補助 DLL を付けてくる。この実行環境のもの以外は外す
$keep = @{ 'win-x64' = 'amd64'; 'win-arm64' = 'arm64' }[$Runtime]
foreach ($arch in 'amd64', 'x86', 'arm64') {
    $dir = Join-Path $out $arch
    if ($arch -ne $keep -and (Test-Path $dir)) { Remove-Item $dir -Recurse -Force }
}

# 説明書。メモ帳（古い Windows 10 のものを含む）で読めるよう、改行は CRLF、文字コードは BOM 付きの UTF-8
$readme = [System.IO.File]::ReadAllText((Join-Path $root 'dist\README.txt'))
$readme = $readme.Replace('{{VERSION}}', $version) -replace "`r?`n", "`r`n"
[System.IO.File]::WriteAllText((Join-Path $out 'README.txt'), $readme, (New-Object System.Text.UTF8Encoding $true))
Write-Host "  パッケージのライセンス表示を作っています…"

# ライセンスの表示。MIT は、配る物の中に著作権とライセンスの表示を入れることを求める。
# このツール自身の LICENSE と、同梱したパッケージ・.NET の実行環境の表示を入れる。
# パッケージは、実際に同梱したもの（deps.json）を nuspec の情報から拾う。依存が増えても漏れないように
$utf8Bom = New-Object System.Text.UTF8Encoding $true
$license = [System.IO.File]::ReadAllText((Join-Path $root 'LICENSE')) -replace "`r?`n", "`r`n"
[System.IO.File]::WriteAllText((Join-Path $out 'LICENSE.txt'), $license, $utf8Bom)

$packages = @{}
foreach ($deps in Get-ChildItem $out -Filter '*.deps.json') {
    $json = Get-Content $deps.FullName -Raw | ConvertFrom-Json
    foreach ($library in $json.libraries.PSObject.Properties) {
        if ($library.Value.type -eq 'package') { $packages[$library.Name] = $true }
    }
}
$nugetRoot = if ($env:NUGET_PACKAGES) { $env:NUGET_PACKAGES } else { Join-Path $HOME '.nuget\packages' }
$bundledRuntime = (Get-Content (Join-Path $out 'PCMonitor.runtimeconfig.json') -Raw | ConvertFrom-Json).runtimeOptions.includedFrameworks

$notices = New-Object System.Collections.Generic.List[string]
$notices.Add("PCMonitor $version に同梱している、ほかの人が作ったもの")
$notices.Add('======================================================')
$notices.Add('')
$notices.Add('PCMonitor 自身のライセンスは LICENSE.txt（MIT）を見てください。')
$notices.Add('次のものは、それぞれの著作権者が MIT ライセンスで公開しているものです。')
$notices.Add('MIT ライセンスの全文は、このファイルの最後にあります。')
$notices.Add('')
$notices.Add('----------------------------------------')
$notices.Add('.NET の実行環境（' + (($bundledRuntime | ForEach-Object { "$($_.name) $($_.version)" }) -join '、') + '）')
$notices.Add('  ライセンス: MIT')
$notices.Add('  著作権: Copyright (c) .NET Foundation and Contributors')
$notices.Add('  入手元: https://github.com/dotnet/runtime 、https://github.com/dotnet/wpf')
$notices.Add('  .NET が含むほかの人の成果物の表示:')
$notices.Add('    https://github.com/dotnet/runtime/blob/main/THIRD-PARTY-NOTICES.TXT')
$notices.Add('    https://github.com/dotnet/wpf/blob/main/THIRD-PARTY-NOTICES.TXT')
foreach ($name in ($packages.Keys | Sort-Object)) {
    $id, $packageVersion = $name -split '/'
    $spec = Get-ChildItem (Join-Path $nugetRoot "$($id.ToLowerInvariant())\$packageVersion") -Filter '*.nuspec' -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $spec) { throw "パッケージの情報（nuspec）が見つかりません: $name" }
    [xml]$nuspec = Get-Content $spec.FullName -Raw
    $meta = $nuspec.package.metadata
    $expression = if ($meta.license -and $meta.license.type -eq 'expression') { $meta.license.'#text' } else { $null }
    # MIT 以外が入ってきたら、表示の書き方を確かめるまで ZIP を作らない
    if ($expression -ne 'MIT') { throw "MIT 以外のライセンスのパッケージが入りました: $name（$expression）。表示の書き方を確かめてください" }
    $notices.Add('')
    $notices.Add('----------------------------------------')
    $notices.Add("$id $packageVersion")
    $notices.Add('  ライセンス: MIT')
    $notices.Add('  著作権: ' + (($meta.copyright -replace '\s+', ' ').Trim() -replace '^©\s*', ''))
    if ($meta.projectUrl) { $notices.Add("  入手元: $($meta.projectUrl)") }
    if ($id -eq 'Microsoft.Diagnostics.Tracing.TraceEvent') {
        $notices.Add("  このパッケージに含まれる Microsoft の補助 DLL（$keep\KernelTraceControl.dll、$keep\msdia140.dll）も同梱しています")
    }
}
$notices.Add('')
$notices.Add('----------------------------------------')
$notices.Add('MIT ライセンスの全文（上の著作権の表示と組み合わせて読みます）')
$notices.Add('')
# LICENSE の本文のうち、著作権の行より後ろ（許諾と免責の部分）を使う
$licenseBody = ($license -split "`r`n") | Select-Object -Skip 4
foreach ($line in $licenseBody) { $notices.Add($line) }
[System.IO.File]::WriteAllText((Join-Path $out 'THIRD-PARTY-NOTICES.txt'), (($notices -join "`r`n").TrimEnd() + "`r`n"), $utf8Bom)

# ZIP は、展開すると PCMonitor-<版>-<実行環境> のフォルダーができる形にする
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory(
    $out, $zip, [System.IO.Compression.CompressionLevel]::Optimal, $true)

$hash = (Get-FileHash $zip -Algorithm SHA256).Hash
[System.IO.File]::WriteAllText($hashFile, "$hash  $name.zip`r`n", (New-Object System.Text.UTF8Encoding $false))

$files = Get-ChildItem $out -Recurse -File
$folderMB = [math]::Round(($files | Measure-Object Length -Sum).Sum / 1MB, 1)
$zipMB = [math]::Round((Get-Item $zip).Length / 1MB, 1)
Write-Host ''
Write-Host "作りました: $zip"
Write-Host "  ZIP $zipMB MB / 展開すると $folderMB MB（$($files.Count) ファイル）"
Write-Host "  SHA-256 $hash"
$included = (Get-Content (Join-Path $out 'PCMonitor.runtimeconfig.json') -Raw | ConvertFrom-Json).runtimeOptions.includedFrameworks
Write-Host ("  同梱した実行環境: " + (($included | ForEach-Object { "$($_.name) $($_.version)" }) -join ', '))
