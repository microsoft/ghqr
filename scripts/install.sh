#!/bin/bash

if ! command -v jq &> /dev/null || ! command -v unzip &> /dev/null || ! command -v wget &> /dev/null
then
    echo "jq, unzip or wget could not be found, please install them."
    exit
fi

arch=$(uname -m)
if [ "$arch" == "aarch64" ]; then
    arch="arm64"
else
    arch="amd64"
fi

latest_ghqr=$(curl -sL https://api.github.com/repos/microsoft/ghqr/releases/latest | jq -r ".tag_name" | cut -c1-)
wget https://github.com/microsoft/ghqr/releases/download/$latest_ghqr/ghqr-linux-$arch.zip -O ghqr.zip
unzip -uj -qq ghqr.zip
rm ghqr.zip
chmod +x ghqr
./ghqr --version
