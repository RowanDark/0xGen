[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Tag,

    [Parameter(Mandatory = $true)]
    [ValidateSet('amd64', 'arm64')]
    [string]$Arch,

    [Parameter(Mandatory = $true)]
    [string]$PayloadDir,

    [Parameter(Mandatory = $true)]
    [string]$OutputDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -Path $PayloadDir -PathType Container)) {
    throw "Payload directory '$PayloadDir' does not exist."
}

switch ($Arch) {
    'amd64' { $wixPlatform = 'x64' }
    'arm64' { $wixPlatform = 'arm64' }
    default { throw "Unsupported architecture: $Arch" }
}

$version = $Tag.TrimStart('v')
if ([string]::IsNullOrWhiteSpace($version) -or $version -eq $Tag) {
    throw "Could not derive version from tag '$Tag'."
}

$msiVersion = $version.Split('-', '+')[0]
if ([string]::IsNullOrWhiteSpace($msiVersion)) {
    throw "Tag '$Tag' does not contain a numeric version component."
}

if ($msiVersion -notmatch '^[0-9]+(\.[0-9]+){0,3}$') {
    throw "Tag '$Tag' yields invalid MSI version '$msiVersion'. Expected 'major.minor.build(.revision)'."
}

$payloadExecutable = Join-Path -Path $PayloadDir -ChildPath 'glyphctl.exe'
if (-not (Test-Path -Path $payloadExecutable -PathType Leaf)) {
    throw "glyphctl.exe not found in payload directory '$PayloadDir'."
}

$tempDir = New-Item -ItemType Directory -Path (Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ([IO.Path]::GetRandomFileName()))
try {
    $repoRoot = (Resolve-Path (Join-Path -Path $PSScriptRoot -ChildPath '..')).Path
    Copy-Item -Path $payloadExecutable -Destination (Join-Path -Path $tempDir -ChildPath 'glyphctl.exe')
    Copy-Item -Path (Join-Path -Path $repoRoot -ChildPath 'README.md') -Destination (Join-Path -Path $tempDir -ChildPath 'README.txt')
    Copy-Item -Path (Join-Path -Path $repoRoot -ChildPath 'LICENSE') -Destination (Join-Path -Path $tempDir -ChildPath 'LICENSE.txt')

    $wxsPath = (Resolve-Path (Join-Path -Path $repoRoot -ChildPath 'packaging/windows/glyphctl.wxs')).Path
    $wixObj = Join-Path -Path $tempDir -ChildPath 'glyphctl.wixobj'

    & candle.exe "-dVersion=$msiVersion" "-dWixPlatform=$wixPlatform" "-dPayloadDir=$tempDir" "-out" $wixObj $wxsPath -ext WixUtilExtension
    if ($LASTEXITCODE -ne 0) {
        throw "candle.exe failed with exit code $LASTEXITCODE"
    }

    if (-not (Test-Path -Path $OutputDir -PathType Container)) {
        New-Item -ItemType Directory -Path $OutputDir | Out-Null
    }

    $outputPath = Join-Path -Path $OutputDir -ChildPath "glyphctl_${Tag}_windows_${Arch}.msi"
    & light.exe "-out" $outputPath $wixObj -ext WixUtilExtension
    if ($LASTEXITCODE -ne 0) {
        throw "light.exe failed with exit code $LASTEXITCODE"
    }

    Write-Host "Built MSI: $outputPath"
}
finally {
    if (Test-Path -Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force
    }
}
