
## What is this?
This is a simple script that tries to read a file (`config.txt`) then parse every line and extract configuration link starting with `vless://` or `vmess://` or `trojan://`.
It grabs five lines at a time and converts to json format and tests using `xray -config -test config.json`
