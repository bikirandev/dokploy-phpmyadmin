# Prints fresh random secrets for Dokploy's Environment tab (Windows PowerShell).
# Keep a copy of VAULT_KEY somewhere safe (a password manager): without it, saved
# database passwords cannot be decrypted after a restore.
function New-RandomBytes([int]$Count) {
    $bytes = New-Object byte[] $Count
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return $bytes
}
"VAULT_KEY=" + [Convert]::ToBase64String((New-RandomBytes 32))
"GATEWAY_TOKEN=" + (-join ((New-RandomBytes 32) | ForEach-Object { $_.ToString("x2") }))
"PMA_TOKEN=" + (-join ((New-RandomBytes 32) | ForEach-Object { $_.ToString("x2") }))
