# PowerShell Script: Get relevant security events for last 7 days

# Define time window (last 7 days)
$StartTime = (Get-Date).AddDays(-7)

# Define relevant event IDs from Security log
$EventIDs = @(
    4624, # Successful logon
    4625, # Failed logon
    4634, # Logoff
    4648, # Logon with explicit credentials
    4672, # Special privileges assigned
    4720, # User account created
    4722, # User account enabled
    4723, # Password change attempt
    4724, # Password reset
    4725, # User account disabled
    4726, # User account deleted
    4732, # User added to a security-enabled local group
    4733, # User removed from a security-enabled local group
    4756, # User added to a security-enabled universal group
    4757, # User removed from a security-enabled universal group
    4768, # Kerberos Authentication (TGT request)
    4769, # Kerberos Service Ticket request
    4776  # Credential validation
)

# Query the Security log
Get-WinEvent -FilterHashtable @{
    LogName='Security';
    Id=$EventIDs;
    StartTime=$StartTime
} | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
    Sort-Object TimeCreated |
    Format-Table -AutoSize
