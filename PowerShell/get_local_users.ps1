# Lists all local users on the server
Get-LocalUser | Select-Object Name, Enabled, LastLogon
