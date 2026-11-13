<#
.SYNOPSIS
    ほかの Windows PC に渡すための ZIP を作る。

.DESCRIPTION
    画面（PCMonitor.exe）とコンソール版（pcmonitor-cli.exe）を、.NET の実行環境ごと
    1 つのフォルダーにまとめて（自己完結型）、ZIP にする。受け取った PC に .NET は要らない。

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
    & dotnet publish (Join-Path $root $project) `
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
