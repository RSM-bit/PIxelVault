# =============================================================================
#  lib\GpgTools.MaskedText.ps1
# -----------------------------------------------------------------------------
#  Whitespace-steganography cover files. Dot-sourced by Invoke-MaskedText.ps1
#  (the Mask/Unmask engine) and by Invoke-CustomerExchange.ps1 (Send -Mask and
#  Receive's auto-unmask). No gpg, no config needed.
#
#  The output is a text file whose ONLY visible content is one line:
#  "This is a blank file that is exactly <N>." Every line after it is spaces and
#  tabs -- invisible in a text editor -- encoding the payload one bit per
#  character (space = 0, tab = 1). Hidden stream = 4-byte big-endian length ||
#  payload. The file is padded to an EXACT N KiB so the stated size is true.
#
#  This is OBFUSCATION, not security. `file`, a hex view, or any entropy or
#  trailing-whitespace scan sees through it, and it costs ~8x the payload size.
#  The PGP layer is the real protection.
# =============================================================================

$script:MaskSentencePattern = '^This is a blank file that is exactly \d+\.\s*$'

# Encode $Payload into a masked text file at $OutPath; returns the stated KiB.
function ConvertTo-MaskedText {
    param([byte[]]$Payload, [string]$OutPath)
    $nl  = "`r`n"
    # 4-byte length header, big-endian. GetBytes returns host order (little-endian
    # on x86), so reverse it to the conventional file/network order.
    $len = [BitConverter]::GetBytes([uint32]$Payload.Length)
    if ([BitConverter]::IsLittleEndian) { [array]::Reverse($len) }
    $stream = $len + $Payload
    # Expand every byte of the stream to 8 characters, MSB first. StringBuilder
    # (not string +=) because the input can be tens of thousands of bytes.
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $stream) {
        for ($i = 7; $i -ge 0; $i--) {
            if ((($b -shr $i) -band 1) -eq 1) { [void]$sb.Append("`t") } else { [void]$sb.Append(' ') }
        }
    }
    $ws = $sb.ToString()
    # Break the long character run into 76-char CRLF lines (cosmetic only; the
    # decoder ignores line breaks and just counts the two characters).
    $wrap = {
        param($str)
        $o = New-Object System.Text.StringBuilder
        for ($pos = 0; $pos -lt $str.Length; $pos += 76) {
            [void]$o.Append($str.Substring($pos, [Math]::Min(76, $str.Length - $pos))); [void]$o.Append("`r`n")
        }
        $o.ToString()
    }
    # First estimate of the stated size N (KiB): the character run plus ~200
    # bytes of slack for the sentence and line endings, rounded up.
    $kib = [int][Math]::Ceiling(($ws.Length + 200) / 1024.0)
    # Find an N whose exact byte count N*1024 can be hit. The digits of N are
    # themselves in the sentence, so a larger N can need another digit; retry
    # with N+1 (at most 8 times) if the content overflows the target.
    for ($tries = 0; $tries -lt 8; $tries++) {
        $target   = $kib * 1024
        $sentence = "This is a blank file that is exactly $kib." + $nl
        $body     = $sentence + (& $wrap $ws)
        $pad      = $target - [System.Text.Encoding]::ASCII.GetByteCount($body)
        if ($pad -lt 0) { $kib++; continue }       # body already exceeds N*1024 -> grow N
        # Fill the remaining bytes to reach exactly N*1024, using space lines so
        # the padding stays inside the "all whitespace after line 1" rule.
        $padsb = New-Object System.Text.StringBuilder
        while ($padsb.Length -lt $pad) {
            $room = $pad - $padsb.Length
            if ($room -le 2) { [void]$padsb.Append((' ' * $room)) }               # no room for a CRLF
            else { [void]$padsb.Append((' ' * [Math]::Min(76, $room - 2)) + $nl) } # leave 2 bytes for CRLF
        }
        $final = $body + $padsb.ToString()
        if ([System.Text.Encoding]::ASCII.GetByteCount($final) -eq $target) {
            [System.IO.File]::WriteAllText($OutPath, $final, (New-Object System.Text.ASCIIEncoding))
            return $kib
        }
        $kib++
    }
    throw "Masking could not converge on an exact KiB size."
}

# Reverse ConvertTo-MaskedText: skip line 1, rebuild the bit string from the
# spaces/tabs, read the 4-byte length, return exactly that many bytes.
function ConvertFrom-MaskedText {
    param([string]$InPath)
    # Split on either line ending; start at index 1 to skip the visible sentence.
    $lines = ([System.IO.File]::ReadAllText($InPath)) -split "`r`n|`n"
    $bits  = New-Object System.Text.StringBuilder
    for ($i = 1; $i -lt $lines.Count; $i++) {
        foreach ($ch in $lines[$i].ToCharArray()) {
            if     ($ch -eq ' ')  { [void]$bits.Append('0') }
            elseif ($ch -eq "`t") { [void]$bits.Append('1') }
        }
    }
    $s = $bits.ToString()
    # Fewer than 32 bits means not even the length header is present.
    if ($s.Length -lt 32) { throw "No hidden data found (not a masked file?)." }
    # Scriptblock: turn the first $n*8 bits of string $b into $n bytes.
    $b2b = {
        param($b, $n)
        $o = New-Object byte[] $n
        for ($k = 0; $k -lt $n; $k++) { $o[$k] = [Convert]::ToByte($b.Substring($k * 8, 8), 2) }
        ,$o
    }
    # First 4 bytes = payload length (big-endian); flip back to host order to read it.
    $lenBytes = & $b2b $s 4
    if ([BitConverter]::IsLittleEndian) { [array]::Reverse($lenBytes) }
    $plLen = [int][BitConverter]::ToUInt32($lenBytes, 0)
    # Make sure the claimed length actually fits in the bits we recovered.
    if ($s.Length -lt 32 + $plLen * 8) { throw "Masked file is truncated or corrupt." }
    # Decode exactly $plLen bytes starting after the 32-bit header; ignore padding.
    return (& $b2b ($s.Substring(32, $plLen * 8)) $plLen)
}

# Cheap check: does the file's first line look like a mask cover?
function Test-MaskedText {
    param([string]$Path)
    try { $first = Get-Content -LiteralPath $Path -TotalCount 1 -ErrorAction Stop } catch { return $false }
    return ("$first" -match $script:MaskSentencePattern)
}

# Mask $Payload to $OutPath and prove it unmasks to the same bytes; deletes the
# output and throws otherwise. Returns the stated KiB.
function Write-MaskedTextVerified {
    param([byte[]]$Payload, [string]$OutPath)
    $kib = ConvertTo-MaskedText -Payload $Payload -OutPath $OutPath
    if ([Convert]::ToBase64String((ConvertFrom-MaskedText -InPath $OutPath)) -ne [Convert]::ToBase64String($Payload)) {
        Remove-Item -LiteralPath $OutPath -Force
        throw "Mask round-trip check FAILED."
    }
    return $kib
}
