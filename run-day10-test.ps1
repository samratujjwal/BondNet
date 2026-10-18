$ErrorActionPreference = "Continue"
docker rm -f bondnet-test 2>$null
docker run -i --name bondnet-test --cap-add=NET_ADMIN --device=/dev/net/tun -v "D:\Samrat Ujjwal\BondNet:/bondnet" ubuntu:24.04 bash /bondnet/day10-docker-test.sh
