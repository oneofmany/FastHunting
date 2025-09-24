# ===== DC Access Audit (Groups + User Rights) =====
# Output file
$OutPath = 'C:\Temp\DC-access-audit.txt'
$dir = Split-Path $OutPath
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
"" | Out-File $OutPath -Encoding UTF8

Import-Module ActiveDirectory -ErrorAction Stop

# Domain DNs
$domain = Get-ADDomain
$domainDN = $domain.DistinguishedName
$builtinDN = "CN=Builtin,$domainDN"

# Target groups (who can log on / manage a DC)
$TargetGroupNames = @(
  'Administrators',            # BUILTIN\Administrators (local admin on DC)
  'Domain Admins',
  'Enterprise Admins',
  'Schema Admins',
  'Server Operators',
  'Account Operators',
  'Backup Operators',
  'Print Operators',
  'Remote Desktop Users',      # RDP allowed by group policy/rights
  'Distributed COM Users'
)

"== GROUP MEMBERSHIPS (recursive) ==" | Out-File $OutPath -Append -Encoding UTF8

foreach ($name in $TargetGroupNames) {
    # Try Builtin first, then domain
    $g = Get-ADGroup -LDAPFilter "(sAMAccountName=$name)" -SearchBase $builtinDN -ErrorAction SilentlyContinue
    if (-not $g) { $g = Get-ADGroup -LDAPFilter "(sAMAccountName=$name)" -SearchBase $domainDN -ErrorAction SilentlyContinue }

    if ($g) {
        "[$($g.SamAccountName)]  DN: $($g.DistinguishedName)" | Out-File $OutPath -Append -Encoding UTF8
        try {
            $members = Get-ADGroupMember -Identity $g.DistinguishedName -Recursive -ErrorAction Stop
            if ($members) {
                foreach ($m in ($members | Sort-Object objectClass, SamAccountName)) {
                    "{0,-10}  {1}" -f $m.objectClass, $m.SamAccountName | Out-File $OutPath -Append -Encoding UTF8
                }
            } else {
                "  (no members)" | Out-File $OutPath -Append -Encoding UTF8
            }
        } catch {
            "  [!] Failed to enumerate members: $($_.Exception.Message)" | Out-File $OutPath -Append -Encoding UTF8
        }
        "" | Out-File $OutPath -Append -Encoding UTF8
    } else {
        "[!] Group not found: $name" | Out-File $OutPath -Append -Encoding UTF8
        "" | Out-File $OutPath -Append -Encoding UTF8
    }
}

# ===== USER RIGHTS: Who can RDP (SeRemoteInteractiveLogonRight) & who is denied =====
"== USER RIGHTS (effective security policy) ==" | Out-File $OutPath -Append -Encoding UTF8

$cfg = Join-Path $env:TEMP "secpol_export.inf"
secedit /export /cfg "$cfg" | Out-Null

# Helper: translate SID -> 'DOMAIN\Name'
function Resolve-Sid {
    param([string]$Sid)
    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $nt = $sidObj.Translate([System.Security.Principal.NTAccount])
        return $nt.Value
    } catch { return $Sid }
}

# Parse rights
$lines = Get-Content $cfg
Remove-Item $cfg -ErrorAction SilentlyContinue

$allow = ($lines | Where-Object { $_ -match '^SeRemoteInteractiveLogonRight\s*=' }) -replace '.*=',''
$deny  = ($lines | Where-Object { $_ -match '^SeDenyRemoteInteractiveLogonRight\s*=' }) -replace '.*=',''

"SeRemoteInteractiveLogonRight (ALLOW RDP):" | Out-File $OutPath -Append -Encoding UTF8
if ([string]::IsNullOrWhiteSpace($allow)) {
    "  (none explicitly assigned in local policy; check GPO)" | Out-File $OutPath -Append -Encoding UTF8
} else {
    $allow.Trim().Split(',') | ForEach-Object {
        $_ = $_.Trim()
        if ($_ -match '^S-1-') { "  $(Resolve-Sid $_)" } else { "  $_" }
    } | Out-File $OutPath -Append -Encoding UTF8
}

"" | Out-File $OutPath -Append -Encoding UTF8
"SeDenyRemoteInteractiveLogonRight (DENY RDP):" | Out-File $OutPath -Append -Encoding UTF8
if ([string]::IsNullOrWhiteSpace($deny)) {
    "  (none explicitly assigned in local policy; check GPO)" | Out-File $OutPath -Append -Encoding UTF8
} else {
    $deny.Trim().Split(',') | ForEach-Object {
        $_ = $_.Trim()
        if ($_ -match '^S-1-') { "  $(Resolve-Sid $_)" } else { "  $_" }
    } | Out-File $OutPath -Append -Encoding UTF8
}

"`nSaved to $OutPath" | Tee-Object -FilePath $OutPath -Append | Out-Null
