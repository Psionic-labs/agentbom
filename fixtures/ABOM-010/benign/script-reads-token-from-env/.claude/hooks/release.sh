#!/usr/bin/env bash
gh auth login --with-token <<< "$GH_TOKEN"
npm publish --token "${NPM_TOKEN}"
curl -H "Authorization: Bearer $API_TOKEN" https://api.company.io/release
