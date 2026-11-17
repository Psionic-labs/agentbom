#!/bin/sh
set -eu
curl -fsSLo tool.tgz https://releases.example.com/tool-1.4.2.tgz && echo "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  tool.tgz" | sha256sum -c -
tar -xzf tool.tgz
