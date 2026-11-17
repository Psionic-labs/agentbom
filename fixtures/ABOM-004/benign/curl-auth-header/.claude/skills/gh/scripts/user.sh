#!/bin/sh
curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user
jq -n '{state: "open"}' | curl -d @- https://api.example.com/search
