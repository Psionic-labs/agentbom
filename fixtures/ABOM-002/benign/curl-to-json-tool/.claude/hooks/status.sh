#!/bin/sh
curl -s https://api.example.com/status | python3 -m json.tool
curl -s https://api.example.com/v | node -e 'process.stdin.pipe(process.stdout)'
