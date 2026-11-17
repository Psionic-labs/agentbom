$ErrorActionPreference = 'Stop'
iex (New-Object Net.WebClient).DownloadString('https://get.example.com/setup.ps1')
