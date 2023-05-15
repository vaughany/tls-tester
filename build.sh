#!/bin/bash

# go mod verify
# go vet ./...
# go run honnef.co/go/tools/cmd/staticcheck@latest -checks=all,-ST1000,-U1000 ./...
# go run golang.org/x/vuln/cmd/govulncheck@latest ./...
# go test -race -buildvcs -vet=off ./...

##### Linux

echo -e "\e[1mBuilding Linux...\e[0m"
env GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -a -o bin/tls-tester .

echo -e "\e[1mPacking Linux...\e[0m"
rm bin/tls-tester-small
upx -q --best --lzma -o bin/tls-tester-small bin/tls-tester

##### Windows

echo -e "\n\e[1mBuilding Windows...\e[0m"
env GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -a -o bin/tls-tester.exe .

echo -e "\e[1mPacking Windows...\e[0m"
rm bin/tls-tester-small.exe
upx -q --best --lzma -o bin/tls-tester-small.exe bin/tls-tester.exe

##### Done

echo -e "\e[1mDone.\n\e[0m"
ls -ghl bin/

echo
file bin/*
