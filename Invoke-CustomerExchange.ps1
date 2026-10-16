# =============================================================================
#  Invoke-CustomerExchange.ps1  --  Send / Receive / keys engine
# -----------------------------------------------------------------------------
#  Package a file the way a customer's API requires and reverse it, plus the
#  one-time key setup for that exchange. Five actions:
#
#    Check            Report which gpg will be used, its version, how the
#                     passphrase will be collected, the keyring folder and the
#                     config file. No crypto, no key needed.
#    NewKeyPair       Generate a SIMPLE key for the exchange: an Ed25519 (or
#                     RSA-4096) signing primary plus one encryption subkey.
#                     Exports the public key and prints the fingerprint. For the
#                     offline-primary layout with separate sign/encrypt/auth
#                     subkeys, use New-GpgKeySet.ps1 instead.
#    ExportPublicKey  Re-export your public key (e.g. the customer lost it).
#    Send             raw file -> Base64 -> Base64 -> gzip -> PGP-encrypt to the
#                     customer's key -> ASCII-armored .asc. With -Mask the .asc
#                     is then wrapped in a cover .txt in one step.
#    Receive          customer .asc (or masked .txt) -> decrypt with your key ->
#                     gunzip -> Base64 decode x2 -> raw file. Each layer is
#                     DETECTED, so a response that skipped one still works.
#
#  USAGE
#      .\Invoke-CustomerExchange.ps1 Check
#      .\Invoke-CustomerExchange.ps1 NewKeyPair -MyUserId 'Jane Doe <jane@example.com>'
#      .\Invoke-CustomerExchange.ps1 Send    .\payload.bin [-Mask]
#      .\Invoke-CustomerExchange.ps1 Receive .\response.asc
#
#  WHY DOUBLE BASE64 THEN GZIP
#    The customer's API specifies it; this script just matches that contract.
#    Base64 twice is wasteful on its own, but gzip at the end reclaims most of
#    the expansion, and the whole thing is verified to round-trip before it is
#    ever encrypted.
#
#  TRUST ANCHOR
#    Send passes --trust-model always so gpg doesn't refuse an unsigned customer
#    key. The real check is CustomerFingerprint: the key file's fingerprint must
#    match the value you got from the customer OUT OF BAND (read over the phone,
#    etc.). With EncryptToSelf = $true the output is also encrypted to your own
#    key, which lets the script decrypt what it just produced and prove the full
#    round trip end to end.
#
#  SETTINGS USED FROM GpgTools.config.psd1
#      all Customer-exchange values, GpgPath, PassphraseMode, MaskedExtension,
#      OutputNaming
#
#  Runs on Windows PowerShell 5.1 and PowerShell 7+. Requires GnuPG 2.2+.
# =============================================================================
[CmdletBinding()]
param(
    # Positional #0: the action. ValidateSet rejects anything else up front.
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('Check', 'NewKeyPair', 'ExportPublicKey', 'Send', 'Receive')][string]$Action,
    # Positional #1: the input file (needed by Send and Receive only).
    [Parameter(Position = 1)][string]$InputPath,
    [string]$OutputPath,
    [switch]$Mask,                      # Send only: wrap the finished .asc in a masked .txt cover
    [string]$ConfigPath,
    # -- per-run overrides of config values; leave unset to use the config file --
    [string]$CustomerPublicKeyPath,
    [string]$CustomerFingerprint,
    [string]$MyKeyFingerprint,
    [string]$MyPrivateKeyPath,
    [string]$MyPublicKeyExportPath,
    [string]$MyUserId,
    [ValidateSet('Ed25519', 'RSA4096')][string]$KeyAlgorithm,
    [bool]  $EncryptToSelf,
    [ValidateSet('Timestamp', 'Original')][string]$OutputNaming,
    [string]$GpgPath,
    [ValidateSet('Auto', 'Pinentry', 'Prompt')][string]$PassphraseMode,
    [string]$MaskedExtension
)
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# Shared plumbing, plus the masking functions (for Send -Mask and Receive's
# auto-unmask). Initialize-GpgTools merges config and locates gpg.
. (Join-Path $PSScriptRoot 'lib\GpgTools.Common.ps1')
. (Join-Path $PSScriptRoot 'lib\GpgTools.MaskedText.ps1')
$null = Initialize-GpgTools -BoundParameters $PSBoundParameters -ConfigPath $ConfigPath

# ---------------------------------------------------------------------------
#  Helpers specific to this engine
# ---------------------------------------------------------------------------

# Validate and import the customer's PUBLIC key before Send uses it. Rejects a
# key file that holds more than one key, is revoked or expired, or can't
# encrypt; and enforces CustomerFingerprint as the trust anchor (only warns if
# that value is still blank). Returns the key's fingerprint.
# It first inspects the file WITHOUT importing (--import-options show-only), so
# a bad key never lands in the keyring, then imports once everything checks out.
function Confirm-CustomerKey {
    $keyFile = (Resolve-Path -LiteralPath $Cfg.CustomerPublicKeyPath).ProviderPath
    $show = Invoke-Gpg @('--batch', '--with-colons', '--import-options', 'show-only', '--import', $keyFile)
    if ($show.ExitCode -ne 0) { throw "gpg could not read the customer key file:`n$($show.Output -join "`n")" }

    # Exactly one primary key ('pub') is required; more than one is ambiguous.
    $pubLines = @($show.Output | Where-Object { $_ -like 'pub:*' })
    if ($pubLines.Count -ne 1) { throw "Customer key file must contain exactly one key (found $($pubLines.Count))." }
    # Field 1 of a pub record is validity: 'r' = revoked, 'e' = expired.
    # Field 11 is the capability string; it must contain 'E' (encrypt).
    $f = $pubLines[0].Split(':')
    if ($f[1] -eq 'r') { throw "Customer key is REVOKED." }
    if ($f[1] -eq 'e') { throw "Customer key is EXPIRED." }
    if ($f[11] -cnotmatch 'E') { throw "Customer key has no usable encryption capability (caps: $($f[11]))." }

    # The fingerprint is on the first 'fpr' record AFTER the 'pub' line.
    $fpr = $null; $seen = $false
    foreach ($l in $show.Output) {
        if ($l -like 'pub:*') { $seen = $true; continue }
        if ($seen -and $l -like 'fpr:*') { $fpr = $l.Split(':')[9].ToUpperInvariant(); break }
    }
    if (-not $fpr) { throw "Could not determine customer key fingerprint." }

    # Trust anchor: the file's fingerprint must equal the out-of-band value.
    if ($Cfg.CustomerFingerprint) {
        if ((Format-Fpr $Cfg.CustomerFingerprint) -ne $fpr) { throw "Customer fingerprint MISMATCH. Key file: $fpr  Configured: $(Format-Fpr $Cfg.CustomerFingerprint)" }
    } else {
        Write-Warning "CustomerFingerprint not set. Confirm with the customer, then set it in $ConfigFile`: $fpr"
    }

    # Everything checks out: import it for real so Send can encrypt to it.
    $imp = Invoke-Gpg @('--batch', '--import', $keyFile)
    if ($imp.ExitCode -ne 0) { throw "Customer key import failed:`n$($imp.Output -join "`n")" }
    return $fpr
}

# gzip / gunzip entirely in memory via .NET GZipStream. The leading comma in
# the return (,$array) stops PowerShell from unrolling the byte array into the
# pipeline as individual bytes.
function Compress-Gzip([byte[]]$Data) {
    $ms = New-Object System.IO.MemoryStream
    $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionLevel]::Optimal, $true)
    try { $gz.Write($Data, 0, $Data.Length) } finally { $gz.Dispose() }   # Dispose flushes the gzip trailer
    return ,$ms.ToArray()
}
function Expand-Gzip([byte[]]$Data) {
    $in  = New-Object System.IO.MemoryStream(, $Data)
    $gz  = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
    $out = New-Object System.IO.MemoryStream
    try { $gz.CopyTo($out) } finally { $gz.Dispose() }
    return ,$out.ToArray()
}

# Unwrap the Send packaging by DETECTING each layer rather than assuming it:
#   * gunzip only if the data starts with the gzip magic bytes (0x1F 0x8B);
#   * then up to two Base64 decodes, each attempted only if the current data is
#     valid Base64 text (right length, right alphabet).
# Returns the recovered bytes PLUS the ordered list of layers actually removed,
# so Receive can warn if a response was wrapped differently than expected.
function Expand-Payload([byte[]]$Data) {
    $stages = New-Object System.Collections.Generic.List[string]
    if ($Data.Length -ge 2 -and $Data[0] -eq 0x1F -and $Data[1] -eq 0x8B) { $Data = Expand-Gzip $Data; $stages.Add('gunzip') }
    for ($i = 0; $i -lt 2; $i++) {
        $txt = [System.Text.Encoding]::ASCII.GetString($Data) -replace '\s', ''
        # Not valid Base64 (empty, wrong length, or illegal characters) -> stop peeling.
        if ($txt.Length -eq 0 -or $txt.Length % 4 -ne 0 -or $txt -notmatch '^[A-Za-z0-9+/]+={0,2}$') { break }
        try { $Data = [Convert]::FromBase64String($txt); $stages.Add('base64') } catch { break }
    }
    [pscustomobject]@{ Data = $Data; Stages = $stages.ToArray() }
}

# ===========================================================================
#  ACTIONS  -- exactly one runs ($Action was validated by the ValidateSet).
# ===========================================================================
switch ($Action) {

    'Check' {
        # Pull the keyring folder out of gpg's own --version banner ("Home: ...").
        $homeLine = (Invoke-GpgRaw @('--version') $null).Output | Where-Object { $_ -like 'Home:*' } | Select-Object -First 1
        [pscustomobject]@{
            Using          = $GpgPath
            Source         = $GpgSource
            Version        = (Get-GpgVersion $GpgPath)
            PassphraseMode = $(if ($UseLoopback) { 'console prompt (loopback)' } else { 'pinentry window' })
            KeyringDir     = ("$homeLine" -replace '^Home:\s*', '')
            ConfigFile     = $ConfigFile
            AllFound       = (($GpgCandidates | ForEach-Object { "$($_.Source) v$($_.Version)" }) -join '; ')
        }
    }

    'NewKeyPair' {
        # Refuse the placeholder user ID so a key isn't generated under a dummy name.
        if ($Cfg.MyUserId -like '*you@company.com*') { throw "Set MyUserId to your name and email first (config file or -MyUserId)." }
        # Algorithm pair: Ed25519 signing primary + Cv25519 encryption subkey, or RSA-4096 for both.
        $algs = if ($Cfg.KeyAlgorithm -eq 'Ed25519') { @{ Primary = 'ed25519'; Sub = 'cv25519' } } else { @{ Primary = 'rsa4096'; Sub = 'rsa4096' } }
        Write-Host "Generating $($Cfg.KeyAlgorithm) key for $($Cfg.MyUserId)."
        # --quick-generate-key makes the primary (cert,sign). -NewPass -> prompt for
        # a new passphrase twice. --status-fd 1 routes the machine-readable
        # KEY_CREATED line to stdout so the fingerprint can be parsed out.
        $gen = Invoke-Gpg @('--status-fd', '1', '--quick-generate-key', $Cfg.MyUserId, $algs.Primary, 'cert,sign', '2y') -NeedPass -NewPass
        $m = [regex]::Match(($gen.Output -join "`n"), 'KEY_CREATED \w ([0-9A-F]{40})')
        if ($gen.ExitCode -ne 0 -or -not $m.Success) { throw "Key generation failed:`n$($gen.Output -join "`n")" }
        $fpr = $m.Groups[1].Value

        # Add the encryption subkey to the primary just created.
        $sub = Invoke-Gpg @('--quick-add-key', $fpr, $algs.Sub, 'encr', '2y') -NeedPass
        if ($sub.ExitCode -ne 0) { throw "Adding encryption subkey failed:`n$($sub.Output -join "`n")" }

        # Write the public key file the customer needs, and tell the user exactly
        # what to do next (put the fingerprint in config, send the public key,
        # back up the private key).
        Export-MyPublicKey $fpr
        [pscustomobject]@{
            MyKeyFingerprint = $fpr
            PublicKeyFile    = $Cfg.MyPublicKeyExportPath
            Expires          = '2 years (extend with: gpg --quick-set-expire <fpr> 2y)'
            NextSteps        = "1) Put the fingerprint in MyKeyFingerprint in $ConfigFile. 2) Send $($Cfg.MyPublicKeyExportPath) to the customer and read them the fingerprint by phone. 3) Back up the private key: & '$GpgPath' --armor --output mykey_PRIVATE.asc --export-secret-keys $fpr (store it securely)."
        }
    }

    'ExportPublicKey' {
        # Make sure the secret key is present (import from backup if needed), then
        # re-write the public key file.
        $fpr = Confirm-MyKey
        Export-MyPublicKey $fpr
        [pscustomobject]@{ MyKeyFingerprint = $fpr; PublicKeyFile = $Cfg.MyPublicKeyExportPath }
    }

    'Send' {
        if (-not $InputPath) { throw "Send needs an input file." }
        $inFile = (Resolve-Path -LiteralPath $InputPath).ProviderPath
        $base   = Get-OutputBase $inFile
        # The armored output; <base>.gz.asc records that it is gzip-then-PGP.
        $out    = Resolve-OutputPath $OutputPath $inFile ($base + '.gz.asc')

        # Validate/import the customer key (the recipient). If EncryptToSelf is on
        # and we have our own fingerprint, add ourselves as a second recipient so
        # the self-decrypt round-trip check below can run.
        $custFpr = Confirm-CustomerKey
        $selfFpr = $null
        if ($Cfg.EncryptToSelf) {
            if ($Cfg.MyKeyFingerprint) { $selfFpr = Confirm-MyKey }
            else { Write-Warning "EncryptToSelf is on but MyKeyFingerprint isn't set; skipping self-encryption and full round-trip check." }
        }

        # Build the packaging: Base64 the raw bytes, Base64 that ASCII text again,
        # then gzip the result. GetBytes between passes because each Base64 result
        # is ASCII text that the next step treats as bytes.
        $raw     = [System.IO.File]::ReadAllBytes($inFile)
        $pass1   = [Convert]::ToBase64String($raw)
        $pass2   = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pass1))
        $gzBytes = Compress-Gzip ([System.Text.Encoding]::ASCII.GetBytes($pass2))

        # Prove the packaging unwraps to the original BEFORE spending a gpg call.
        # Expand-Payload should peel gzip + one base64 back to $pass1.
        $chk = Expand-Payload $gzBytes
        if ([Convert]::ToBase64String($chk.Data) -ne $pass1) { throw "Pre-encryption round-trip check FAILED." }

        $tmp = New-TempPath '.gz'; $tmpDec = $null
        try {
            [System.IO.File]::WriteAllBytes($tmp, $gzBytes)
            # Encrypt the gz blob to the customer (and optionally to self).
            #   --compress-algo none : the payload is already gzipped, don't double-compress
            #   --personal-cipher-preferences AES256... : prefer AES-256 among what the key allows
            #   --set-filename <base>.gz : the name stored inside the PGP packet (not the real file name)
            $encArgs = @('--batch', '--yes', '--trust-model', 'always', '--compress-algo', 'none', '--armor',
                         '--personal-cipher-preferences', 'AES256 AES192 AES',
                         '--set-filename', ($base + '.gz'), '--recipient', $custFpr)
            if ($selfFpr) { $encArgs += @('--recipient', $selfFpr) }
            $encArgs += @('--output', $out, '--encrypt', $tmp)
            $enc = Invoke-Gpg $encArgs
            if ($enc.ExitCode -ne 0 -or -not (Test-Path $out)) { throw "Encryption failed:`n$($enc.Output -join "`n")" }

            # Confirm the customer key is actually among the recipients, by reading
            # the output's packet list (--pinentry-mode cancel: never prompt here)
            # and matching the recipient key IDs against the customer's key IDs.
            $pkt    = (Invoke-Gpg @('--batch', '--list-packets', '--pinentry-mode', 'cancel', $out)).Output -join "`n"
            $pktIds = @([regex]::Matches($pkt, 'keyid ([0-9A-Fa-f]{16})') | ForEach-Object { $_.Groups[1].Value.ToUpperInvariant() })
            $custIds = Get-KeyIds $custFpr
            if (-not ($pktIds | Where-Object { $custIds -contains $_ })) { throw "Output is not encrypted to the customer key (packet IDs: $($pktIds -join ', '))." }

            # Full round trip through OUR key (only if we encrypted to self):
            # decrypt the .asc and confirm the unwrapped bytes equal $pass1.
            $roundTrip = 'skipped (no self key)'
            if ($selfFpr) {
                $tmpDec = New-TempPath '.dec'
                $dec = Invoke-Gpg @('--yes', '--output', $tmpDec, '--decrypt', $out) -NeedPass
                if ($dec.ExitCode -ne 0) { throw "Self-decrypt check failed:`n$($dec.Output -join "`n")" }
                $back = Expand-Payload ([System.IO.File]::ReadAllBytes($tmpDec))
                if ([Convert]::ToBase64String($back.Data) -ne $pass1) { throw "Full round-trip check FAILED." }
                $roundTrip = 'OK (' + ($back.Stages -join ' > ') + ')'
            }
        } finally { Remove-TempFile $tmp; Remove-TempFile $tmpDec }

        # Optional cover: wrap the finished .asc in a masked .txt. The verified
        # masker throws (and deletes the cover) on a bad round trip, so the .asc
        # is only removed after the cover is proven good.
        $finalOut = $out
        $maskKib  = $null
        if ($Mask) {
            $maskOut = Join-Path (Split-Path -Parent $out) ($base + $Cfg.MaskedExtension)
            if (Test-Path -LiteralPath $maskOut) { throw "Masked output already exists: $maskOut" }
            $maskKib = Write-MaskedTextVerified -Payload ([System.IO.File]::ReadAllBytes($out)) -OutPath $maskOut
            Remove-Item -LiteralPath $out -Force
            $finalOut = $maskOut
        }

        [pscustomobject]@{
            Output          = $finalOut
            CustomerKey     = $custFpr
            EncryptedToSelf = [bool]$selfFpr
            InputBytes      = $raw.Length
            OutputBytes     = (Get-Item -LiteralPath $finalOut).Length
            RecipientCheck  = 'OK'
            RoundTrip       = $roundTrip
            Masked          = $(if ($Mask) { "yes ($maskKib KiB cover)" } else { 'no' })
        }
    }

    'Receive' {
        if (-not $InputPath) { throw "Receive needs the customer's encrypted file." }
        $inFile = (Resolve-Path -LiteralPath $InputPath).ProviderPath
        # Default output: strip a trailing .asc/.gpg/.pgp/.txt and a .gz, then add
        # .decrypted. (A masked cover is a .txt; a bare .asc is the common case.)
        $stem   = [System.IO.Path]::GetFileName($inFile) -replace '(\.(asc|gpg|pgp|txt))$', '' -replace '\.gz$', ''
        $out    = Resolve-OutputPath $OutputPath $inFile ($stem + '.decrypted')

        # Our private key must be available to decrypt.
        $myFpr = Confirm-MyKey
        # If the input is a masked cover, unmask it to a temp .asc first; Receive
        # then decrypts that. $wasMasked is reported back to the caller.
        $decInput = $inFile; $tmpAsc = $null; $wasMasked = $false
        if (Test-MaskedText $inFile) {
            $tmpAsc = New-TempPath '.asc'
            [System.IO.File]::WriteAllBytes($tmpAsc, (ConvertFrom-MaskedText -InPath $inFile))
            $decInput = $tmpAsc; $wasMasked = $true
        }
        $tmp = New-TempPath '.dec'
        try {
            # Decrypt with --status-fd 1 so the machine-readable status lines
            # (ENC_TO, GOODSIG, ...) come back on stdout for inspection.
            $dec = Invoke-Gpg @('--yes', '--status-fd', '1', '--output', $tmp, '--decrypt', $decInput) -NeedPass
            $status = $dec.Output -join "`n"
            if ($dec.ExitCode -ne 0 -and $status -notmatch 'DECRYPTION_OKAY') { throw "Decryption failed:`n$status" }

            # Warn if the file wasn't actually addressed to our configured key
            # (ENC_TO lists the recipient key IDs gpg saw).
            $encTo = @([regex]::Matches($status, 'ENC_TO ([0-9A-F]{16})') | ForEach-Object { $_.Groups[1].Value })
            $mine  = Get-KeyIds $myFpr
            if (-not ($encTo | Where-Object { $mine -contains $_ })) { Write-Warning "File wasn't addressed to your configured key (ENC_TO: $($encTo -join ', '))." }

            # Report any signature status for information (the exchange isn't
            # necessarily signed, so 'unsigned' is normal).
            $sig = 'unsigned'
            if     ($status -match 'GOODSIG \S+ (.+)') { $sig = "GOOD signature: $($Matches[1])" }
            elseif ($status -match 'BADSIG')           { $sig = 'BAD SIGNATURE (file altered or wrong key)' }
            elseif ($status -match 'NO_PUBKEY|ERRSIG') { $sig = "signed, but signer's key not in keyring" }

            # Peel gzip + the two Base64 layers back to the original bytes.
            $res = Expand-Payload ([System.IO.File]::ReadAllBytes($tmp))
            [System.IO.File]::WriteAllBytes($out, $res.Data)
        } finally { Remove-TempFile $tmp; Remove-TempFile $tmpAsc }

        # The expected layering for THIS exchange is gunzip then two base64s;
        # warn (don't fail) if a response was wrapped differently.
        $layers = $res.Stages -join ' > '
        if ($layers -ne 'gunzip > base64 > base64') { Write-Warning "Unexpected layering: '$layers'. Check the output before relying on it." }

        [pscustomobject]@{
            Output      = $out
            OutputBytes = $res.Data.Length
            Unmasked    = $wasMasked
            Layers      = $layers
            Signature   = $sig
        }
    }
}
