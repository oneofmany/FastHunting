# Lists all local users on the server
# Output file
$OutPath = 'C:\Temp\local-users.txt'

# Ensure the folder exists
$dir = Split-Path $OutPath
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

# Get local users and write as plain text
Get-LocalUser |
    Select-Object Name, Enabled, LastLogon |
    Sort-Object Name |
    Format-Table -AutoSize |
    Out-String |
    Out-File -FilePath $OutPath -Encoding UTF8

Write-Host "Saved to $OutPath"



