if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
    $arch = "amd64"
} elseif ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
    $arch = "arm64"
} else {
    Write-Host "Unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)"
    exit
}

$latest_ghqr=$(iwr https://api.github.com/repos/microsoft/ghqr/releases/latest).content | convertfrom-json | Select-Object -ExpandProperty tag_name
iwr https://github.com/microsoft/ghqr/releases/download/$latest_ghqr/ghqr-win-$arch.zip -OutFile ghqr.zip
Expand-Archive -Path ghqr.zip -DestinationPath ./ghqr_bin
Get-ChildItem -Path ./ghqr_bin -Recurse -File | ForEach-Object { Move-Item -Path $_.FullName -Destination . -Force }
Remove-Item -Path ./ghqr_bin -Recurse -Force
Remove-Item -Path ghqr.zip
.\ghqr.exe --version
