# =============================================================================
#  Invoke-NestedProtect.ps1  --  Protect / Unprotect engine
# -----------------------------------------------------------------------------
#  Nest a file inside TWO independent PGP layers (defense in depth; opening it
#  needs BOTH private keys). The middle blob that gets encrypted to the OUTER
#  key is framed like this:
#
#      decoy text  ||  inner.gpg (encrypted to the INNER key)  ||  MAGIC(8)  ||  len(8)
#
#  where len is the inner.gpg byte length as a big-endian UInt64 and MAGIC marks
#  a valid nest. Unprotect decrypts the outer layer, reads the last 16 bytes to
#  find the inner blob's length, carves it out, and decrypts it with the INNER
#  key.
#
#  SECURITY HONESTY
#    This is two-key DEFENSE IN DEPTH, not an undetectable hidden volume. Once
#    the outer layer is decrypted, the appended inner ciphertext is plainly
#    visible after the decoy text, so an inspector can tell a second layer
#    exists. The value is that compromising ONE key (or one passphrase) is not
#    enough to read the real payload.
#
#  USAGE
#      .\Invoke-NestedProtect.ps1 Protect   .\secret.bin             # -> <timestamp>.asc
#      .\Invoke-NestedProtect.ps1 Unprotect .\20261015T184500Z.asc   # -> <stem>.decrypted
#
#  SETTINGS USED FROM GpgTools.config.psd1
#      InnerFingerprint, OuterFingerprint, MyKeyFingerprint (inner fallback),
#      DecoyText, OutputNaming, GpgPath, PassphraseMode
#
#  Runs on Windows PowerShell 5.1 and PowerShell 7+. Requires GnuPG 2.2+.
# =============================================================================
[CmdletBinding()]
param(
    # Positional #0: which operation. ValidateSet rejects anything else.
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('Protect', 'Unprotect')][string]$Action,
    # Positional #1: the secret file (Protect) or the protected .asc (Unprotect).
    [Parameter(Mandatory = $true, Position = 1)][string]$InputPath,
    [string]$OutputPath,
    [string]$ConfigPath,
    # -- per-run overrides of config values; leave unset to use the config file --
    [string]$InnerFingerprint,
    [string]$OuterFingerprint,
    [string]$MyKeyFingerprint,
    [string]$DecoyText,
    [ValidateSet('Timestamp', 'Original')][string]$OutputNaming,
    [string]$GpgPath,
    [ValidateSet('Auto', 'Pinentry', 'Prompt')][string]$PassphraseMode
)
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # hide any progress bars from .NET calls

# Shared plumbing (config merge, gpg locator, Invoke-Gpg, helpers).
. (Join-Path $PSScriptRoot 'lib\GpgTools.Common.ps1')
# This engine DOES use gpg, so no -NoGpg: Initialize-GpgTools also locates gpg
# and sets $GpgPath / $UseLoopback.
$null = Initialize-GpgTools -BoundParameters $PSBoundParameters -ConfigPath $ConfigPath

# 8-byte marker written just before the length trailer: ASCII "NESTPD" followed
# by a version (1,0). Unprotect checks these exact bytes before trusting the
# length, so a file that isn't ours (or an outer layer that decrypted to the
# wrong thing) is rejected cleanly instead of mis-parsed.
$script:NestMagic = [byte[]](0x4E,0x45,0x53,0x54,0x50,0x44,0x01,0x00)   # "NESTPD" + version 1,0

# Work out the inner and outer fingerprints for this run:
#   * inner falls back to MyKeyFingerprint if InnerFingerprint is blank, so a
#     single-key setup still works;
#   * outer is required (there is no sensible fallback for the second layer);
#   * if the two are equal there is really only one layer, which defeats the
#     purpose -- warn loudly but proceed, since the user may be testing.
function Resolve-NestKeys {
    $inner = if ($Cfg.InnerFingerprint) { Format-Fpr $Cfg.InnerFingerprint }
             elseif ($Cfg.MyKeyFingerprint) { Format-Fpr $Cfg.MyKeyFingerprint }
             else { throw "Set InnerFingerprint (or MyKeyFingerprint) in $ConfigFile." }
    if (-not $Cfg.OuterFingerprint) { throw "Set OuterFingerprint in $ConfigFile to a second key (different from the inner key)." }
    $outer = Format-Fpr $Cfg.OuterFingerprint
    if ($inner -eq $outer) { Write-Warning "Inner and outer keys are the SAME -- this collapses to a single layer, no two-key protection." }
    [pscustomobject]@{ Inner = $inner; Outer = $outer }
}

# Resolve the input path and the two keys once, up front.
$inFile = (Resolve-Path -LiteralPath $InputPath).ProviderPath
$keys   = Resolve-NestKeys

switch ($Action) {

    'Protect' {
        # Output defaults to <timestamp-or-stem>.asc next to the input.
        $out = Resolve-OutputPath $OutputPath $inFile ((Get-OutputBase $inFile) + '.asc')
        # Two temp files: the inner ciphertext, and the framed "combined" blob.
        # Both are removed in the finally block no matter what happens.
        $tmpInner = New-TempPath '.gpg'; $tmpComb = New-TempPath '.bin'
        try {
            # 1. INNER layer: encrypt the secret to the inner key (binary .gpg).
            #    --trust-model always so gpg doesn't balk at an unsigned recipient key.
            $e1 = Invoke-Gpg @('--batch', '--yes', '--trust-model', 'always', '--recipient', $keys.Inner, '--output', $tmpInner, '--encrypt', $inFile)
            if ($e1.ExitCode -ne 0 -or -not (Test-Path $tmpInner)) { throw "Inner encryption failed:`n$($e1.Output -join "`n")" }
            $innerBytes = [System.IO.File]::ReadAllBytes($tmpInner)

            # 2. COMBINED blob = decoy text || inner.gpg || MAGIC(8) || len(8, big-endian).
            #    len is the inner length so Unprotect can carve the inner blob back out.
            $decoyBytes = [System.Text.Encoding]::UTF8.GetBytes($Cfg.DecoyText)
            $lenBytes = [BitConverter]::GetBytes([uint64]$innerBytes.LongLength)
            if ([BitConverter]::IsLittleEndian) { [array]::Reverse($lenBytes) }   # -> big-endian
            $combined = $decoyBytes + $innerBytes + $script:NestMagic + $lenBytes
            [System.IO.File]::WriteAllBytes($tmpComb, $combined)

            # 3. OUTER layer: encrypt the combined blob to the outer key, armored (.asc).
            #    Decrypting ONLY this layer yields the decoy text followed by the
            #    (still-encrypted) inner blob.
            $e2 = Invoke-Gpg @('--batch', '--yes', '--trust-model', 'always', '--armor', '--recipient', $keys.Outer, '--output', $out, '--encrypt', $tmpComb)
            if ($e2.ExitCode -ne 0 -or -not (Test-Path $out)) { throw "Outer encryption failed:`n$($e2.Output -join "`n")" }
        } finally { Remove-TempFile $tmpInner; Remove-TempFile $tmpComb }

        [pscustomobject]@{
            Output      = $out
            InnerKey    = $keys.Inner
            OuterKey    = $keys.Outer
            InputBytes  = (Get-Item -LiteralPath $inFile).Length
            OutputBytes = (Get-Item -LiteralPath $out).Length
            Note        = 'Two layers. Unprotect needs BOTH keys. Decrypting only the outer yields the decoy.'
        }
    }

    'Unprotect' {
        # Recovered file defaults to <stem>.decrypted (strip a .asc/.gpg/.pgp
        # extension off the input name first) in the input's folder.
        $stem = [System.IO.Path]::GetFileName($inFile) -replace '(\.(asc|gpg|pgp))$', ''
        $out  = Resolve-OutputPath $OutputPath $inFile ($stem + '.decrypted')
        $tmpComb = New-TempPath '.bin'; $tmpInner = New-TempPath '.gpg'
        try {
            # 1. OUTER decrypt (outer key). Clear the cached passphrase first so
            #    that if the inner and outer keys have DIFFERENT passphrases each
            #    is prompted/agent-checked on its own.
            $script:Passphrase = $null
            $d1 = Invoke-Gpg @('--yes', '--output', $tmpComb, '--decrypt', $inFile) -NeedPass
            if ($d1.ExitCode -ne 0) { throw "Outer decryption failed:`n$($d1.Output -join "`n")" }
            $combined = [System.IO.File]::ReadAllBytes($tmpComb)

            # 2. Parse the 16-byte trailer: last 16 bytes = MAGIC(8) || len(8).
            if ($combined.Length -lt 16) { throw "Not a protected file (too short)." }
            $magic = $combined[($combined.Length - 16)..($combined.Length - 9)]
            # SequenceEqual: byte-exact comparison of the marker. A mismatch means
            # this isn't a Protect file, or the outer layer decrypted to garbage.
            if (-not [System.Linq.Enumerable]::SequenceEqual([byte[]]$magic, $script:NestMagic)) { throw "Bad or missing nest marker -- not a Protect file, or outer decrypted to the wrong thing." }
            $lenBytes = $combined[($combined.Length - 8)..($combined.Length - 1)]
            if ([BitConverter]::IsLittleEndian) { [array]::Reverse($lenBytes) }   # big-endian -> host order
            $innerLen = [BitConverter]::ToUInt64([byte[]]$lenBytes, 0)
            # The inner blob sits just before the 16-byte trailer; everything
            # before it is the decoy text.
            $innerStart = $combined.Length - 16 - [int]$innerLen
            if ($innerStart -lt 0) { throw "Nest length is inconsistent with file size." }
            $innerBytes = New-Object byte[] ([int]$innerLen)
            [Array]::Copy($combined, $innerStart, $innerBytes, 0, [int]$innerLen)
            $decoyBytes = New-Object byte[] $innerStart
            [Array]::Copy($combined, 0, $decoyBytes, 0, $innerStart)
            [System.IO.File]::WriteAllBytes($tmpInner, $innerBytes)

            # 3. INNER decrypt (inner key). Clear the passphrase cache again for
            #    the same reason as the outer decrypt.
            $script:Passphrase = $null
            $d2 = Invoke-Gpg @('--yes', '--output', $out, '--decrypt', $tmpInner) -NeedPass
            if ($d2.ExitCode -ne 0) { throw "Inner decryption failed:`n$($d2.Output -join "`n")" }
        } finally { Remove-TempFile $tmpComb; Remove-TempFile $tmpInner }

        [pscustomobject]@{
            Output      = $out
            OutputBytes = (Get-Item -LiteralPath $out).Length
            Decoy       = [System.Text.Encoding]::UTF8.GetString($decoyBytes)   # the outer-layer decoy, for confirmation
            Layers      = 'outer + inner (both keys used)'
        }
    }
}
