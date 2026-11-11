#Requires -Version 7
# Makes the web pages that the setup program's Release notes and README buttons show: converts each
# markdown file to HTML and puts it in DocPage.html. Run by the build (PrelPtpSetup.vcxproj), which
# embeds the pages in PrelPtpSetup.exe (PrelPtpSetup.rc2).
#
#   pwsh -File MakeDocPages.ps1 -OutDir <folder> <file.md> [<file.md>...]
#
# Each <name>.md becomes <OutDir>\<name>.html.
param(
  [Parameter(Mandatory)][string]$OutDir,
  [Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Markdown
)
$ErrorActionPreference = 'Stop'

# relative links (to the source files, LICENSE or the releases) go to the repository on GitHub
$repository = [Uri]'https://github.com/production-robots/PrelPtp/blob/main/'

$template = Get-Content -Raw -Encoding utf8 (Join-Path $PSScriptRoot 'DocPage.html')
New-Item -ItemType Directory -Force $OutDir | Out-Null
foreach ($file in $Markdown) {
  # ConvertFrom-Markdown handles GitHub's tables, and gives headings GitHub's ids, which the
  # README's contents links use
  $html = (Get-Content -Raw -Encoding utf8 $file | ConvertFrom-Markdown).Html
  $html = $html -replace '(?<=<a href=")([^"]+)(?=")', {
    $href = $_.Groups[1].Value
    if ($href -match '^([a-z][a-z0-9+.-]*:|#)') { $href } else { [Uri]::new($repository, $href).AbsoluteUri }
  }
  $title = if ($html -match '<h1[^>]*>(.*?)</h1>') { $Matches[1] -replace '<[^>]+>', '' } else { 'PREL PTP' }
  $page = $template.Replace('<!--PRELPTP:TITLE-->', $title).Replace('<!--PRELPTP:CONTENT-->', $html)
  $out = Join-Path $OutDir ([IO.Path]::GetFileNameWithoutExtension($file) + '.html')
  [IO.File]::WriteAllText($out, $page, [Text.UTF8Encoding]::new($false))
}
