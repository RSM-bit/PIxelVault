#Requires -Version 7.4
<#
===============================================================================================================
 PixelVault.ps1
===============================================================================================================

.SYNOPSIS
  Pack any file (typically a PGP-encrypted .asc) into a PNG image that looks like pure colour noise, under an
  independent AES-256-GCM passphrase layer by default, and unpack it again byte-for-byte.

.DESCRIPTION
  PURPOSE
    A defence-in-depth wrapper for files you keep in cloud storage. The threat model is: the cloud provider's
    storage is breached AND the PGP layer later turns out to be weak (ROCA-style key-generation flaw, a future
    break of the public-key algorithm, etc.). The outer layer here is purely symmetric (passphrase -> PBKDF2 ->
    AES-256-GCM), shares no key material with PGP, and can't fail the same way. An attacker needs BOTH the PGP
    private key (or a break of it) AND this passphrase. The image is a container, not steganography: it stops
    casual recognition and strips PGP metadata (recipient key id, algorithm, size) but is obviously not a photo.

  TWO WAYS TO USE IT
    1) Dot-source it and call the two functions (batch / pipeline use):
           . .\PixelVault.ps1
           ConvertTo-PixelVault    file  -> PNG (or the PNG as base64 text with -Base64)
           ConvertFrom-PixelVault  PNG or base64 text -> original file (original filename restored, SHA-256 verified)
    2) Run it directly with an Action (what GpgTools.Menu.ps1 does):
           .\PixelVault.ps1 Pack   .\secrets.asc [-OutFile x.png] [-NoEncryption] [-Base64] [-Force]
           .\PixelVault.ps1 Unpack .\IMG_20261009_140612_347.png [-OutFile name] [-Force]
       With no Action the script only defines the functions (so dot-sourcing is unchanged).

  CONTAINER FORMAT (version 1)
    All of this is laid into the RGB pixel bytes of the image, row-major, starting at pixel (0,0). Pixels left
    over after the payload are filled with CSPRNG noise so the payload end is not visible.

      offset  size  field          notes
      ------  ----  -------------  ---------------------------------------------------------------------
        0       1   version        always 1
        1       1   flags          bit 0 = 1 if the body is encrypted, 0 if stored in the clear
        2       4   pbkdf2Iter     int32 little-endian; 0 when not encrypted
        6      16   salt           random per file (zeros when not encrypted)
       22      12   nonce          random per file; AES-GCM nonce (zeros when not encrypted)
       34       4   bodyLen        int32 little-endian; length of body in bytes
       38      16   tag            AES-GCM authentication tag (zeros when not encrypted)
       54   bodyLen body           ciphertext (or plaintext with -NoEncryption)

    The 38-byte header (offsets 0..37) is passed to AES-GCM as Associated Data, so it is authenticated: an
    attacker can't silently change the iteration count, salt, nonce or length without the tag failing.

    body (before encryption) =  nameLen(2, uint16 LE) | utf8 original filename | sha256(32) of data | data
    key  =  PBKDF2-HMAC-SHA256(passphrase UTF-8 bytes, salt, pbkdf2Iter) -> 32 bytes

    Every multi-byte integer in the container is little-endian regardless of the host CPU, so an image made on
    any machine decodes on any other. PNG's own chunk fields are big-endian as the PNG spec requires.

  WHY PNG AND NOT JPEG
    JPEG is lossy; the decoder would get back approximately-right pixel values and the payload would be
    destroyed. PNG is lossless. Store the images as plain files (Drive, OneDrive, S3, ...). Never put them in a
    photo service (Google Photos, iCloud Photos, social media) that recompresses, resizes or strips images.

  WHY THE IMAGE IS WRITTEN BY HAND
    No image library is needed; the script emits the three mandatory PNG chunks itself (IHDR, IDAT, IEND) with
    8-bit RGB, no interlace, and filter type 0 on every scanline. The decoder refuses any other layout, which
    is also how it detects an image that was re-saved by another program.

  DEPENDENCIES
    PowerShell 7.4+ only. Everything used (AesGcm, Rfc2898DeriveBytes.Pbkdf2, SHA256.HashData, ZLibStream,
    RandomNumberGenerator) ships in the .NET 8 runtime bundled with PowerShell 7. Windows PowerShell 5.1 lacks
    these, hence the #Requires line. The CRC-32 helper is a few lines of C# compiled at load time with Add-Type
    (works offline; blocked only under constrained-language policies such as WDAC/AppLocker).

  PASSPHRASE HANDLING
    The passphrase is read as a SecureString (no echo), converted to bytes only for the PBKDF2 call, and the
    byte arrays for passphrase and key are zeroed immediately afterwards. The PowerShell string that briefly
    holds the plaintext cannot be zeroed (strings are immutable in .NET); this is a known limit of PowerShell,
    not something the script can fix. Losing the passphrase means losing the file; there is no recovery.

.EXAMPLE
  . .\PixelVault.ps1
  ConvertTo-PixelVault -Path .\secrets.asc
    # asks for the passphrase twice, writes IMG_20261009_140612_347.png next to secrets.asc

.EXAMPLE
  ConvertFrom-PixelVault -Path .\IMG_20261009_140612_347.png
    # asks for the passphrase, restores secrets.asc next to the image, refuses to overwrite an existing file

.EXAMPLE
  Get-ChildItem .\vault\*.asc | ConvertTo-PixelVault -Base64 -NamePrefix 'PXL_'
    # batch; each image gets its own timestamp name and is written as base64 text (.png.b64)

.EXAMPLE
  ConvertTo-PixelVault -Path .\notes.txt -NoEncryption
    # obfuscation only; anyone with this script can unpack it without a passphrase

.EXAMPLE
  .\PixelVault.ps1 Pack .\secrets.asc
    # same as the first example, without dot-sourcing
#>
# Command-line entry point (see "TWO WAYS TO USE IT" above). EVERY parameter is
# optional and there is no Mandatory anywhere, so dot-sourcing the file with no
# arguments (`. .\PixelVault.ps1`) binds nothing, leaves $Action empty, and the
# dispatch block at the very bottom does nothing -- the file just defines the two
# functions, exactly as before this entry point was added. The menu, by contrast,
# invokes the file WITH an Action, which triggers the dispatch block.
[CmdletBinding()]
param(
    [Parameter(Position = 0)][ValidateSet('Pack', 'Unpack')][string]$Action,  # Pack = encode, Unpack = decode; empty = just load functions
    [Parameter(Position = 1)][string]$InputPath,                              # source file (Pack) or image (Unpack)
    [string]$OutFile,                                                         # explicit output; omitted = auto-name / restore original name
    [switch]$NoEncryption,   # Pack only: skip the AES layer (obfuscation only)
    [switch]$Base64,         # Pack only: write the PNG as base64 text (.png.b64)
    [string]$NamePrefix = 'IMG_',                                             # prefix for an auto-generated image name
    [switch]$Force                                                           # overwrite an existing output file
)

# Strict mode: referencing an unset variable, or a property that doesn't exist, is an error rather than silently
# $null. In a tool that writes encrypted data, a silently-null variable is how you get an undecryptable file.
Set-StrictMode -Version Latest

# -------------------------------------------------------------------------------------------------------------
# CRC-32 (ISO 3309 / ITU-T V.42, polynomial 0xEDB88320, reflected) as required by the PNG specification for
# every chunk. .NET has no public CRC-32 for PNG, so a tiny C# class is compiled once per session. The guard
# makes re-dot-sourcing the script harmless (Add-Type would otherwise throw "type already exists").
# Compute() takes two arrays because PNG's CRC covers the 4-byte chunk type followed by the chunk data,
# and concatenating them in PowerShell would copy the whole IDAT payload for nothing.
# -------------------------------------------------------------------------------------------------------------
if (-not ('PixelVault.Crc32' -as [type])) {
    Add-Type -TypeDefinition @'
namespace PixelVault {
  public static class Crc32 {
    static readonly uint[] T = Build();
    static uint[] Build() {
      var t = new uint[256];
      for (uint n = 0; n < 256; n++) {
        uint c = n;
        for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        t[n] = c;
      }
      return t;
    }
    public static uint Compute(byte[] a, byte[] b) {
      uint c = 0xFFFFFFFFu;
      foreach (var x in a) c = T[(c ^ x) & 0xFF] ^ (c >> 8);
      foreach (var x in b) c = T[(c ^ x) & 0xFF] ^ (c >> 8);
      return c ^ 0xFFFFFFFFu;
    }
  }
}
'@
}

# -------------------------------------------------------------------------------------------------------------
# Script-scope constants
# -------------------------------------------------------------------------------------------------------------
# The 8-byte PNG file signature: high-bit byte, "PNG", CRLF, Ctrl-Z, LF. Fixed by the PNG spec.
$script:PngSig   = [byte[]](0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
# Size of the container header (see table in the header comment): 1+1+4+16+12+4 = 38 bytes.
$script:HeaderLen = 38
# AES-GCM authentication tag length. 16 bytes (128-bit) is the maximum and the recommended size.
$script:TagLen    = 16

# -------------------------------------------------------------------------------------------------------------
# Byte-order helpers
# PNG chunk lengths, dimensions and CRCs are big-endian (network order). The container's own integers are
# little-endian because BinaryWriter writes little-endian; the reader below therefore reads little-endian
# explicitly instead of trusting the host's byte order.
# -------------------------------------------------------------------------------------------------------------

# uint32 -> 4 bytes, big-endian. The leading comma returns the array as a single object instead of letting
# PowerShell unroll it into four separate pipeline items.
function Get-BEBytes([uint32]$Value) {
    $b = [BitConverter]::GetBytes($Value)                     # host order
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }  # flip to big-endian when needed
    , $b
}

# 4 bytes at $Offset, big-endian -> uint32. Used while walking PNG chunks.
function Read-BEUInt32([byte[]]$Buf, [int]$Offset) {
    $t = [byte[]]::new(4)
    [Buffer]::BlockCopy($Buf, $Offset, $t, 0, 4)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($t) }
    [BitConverter]::ToUInt32($t, 0)
}

# $Count bytes at $Offset, little-endian -> uint64, assembled byte by byte so the result does not depend on
# the CPU's native byte order. Used for every integer inside the container.
function Read-LEUInt([byte[]]$Buf, [int]$Offset, [int]$Count) {
    [uint64]$v = 0
    for ($i = $Count - 1; $i -ge 0; $i--) { $v = ($v -shl 8) -bor $Buf[$Offset + $i] }
    $v
}

# Copy $Count bytes starting at $Offset into a fresh array. Leading comma again prevents unrolling.
function Get-Slice([byte[]]$Buf, [int]$Offset, [int]$Count) {
    $r = [byte[]]::new($Count)
    [Buffer]::BlockCopy($Buf, $Offset, $r, 0, $Count)
    , $r
}

# -------------------------------------------------------------------------------------------------------------
# PNG chunk writer: length(4, BE) | type(4 ASCII) | data | crc32(4, BE) over type+data
# -------------------------------------------------------------------------------------------------------------
function Write-PngChunk([System.IO.Stream]$Stream, [string]$Type, [byte[]]$Data) {
    $tb = [Text.Encoding]::ASCII.GetBytes($Type)
    $Stream.Write((Get-BEBytes $Data.Length), 0, 4)
    $Stream.Write($tb, 0, 4)
    if ($Data.Length) { $Stream.Write($Data, 0, $Data.Length) }   # IEND has zero-length data
    $Stream.Write((Get-BEBytes ([PixelVault.Crc32]::Compute($tb, $Data))), 0, 4)
}

# -------------------------------------------------------------------------------------------------------------
# Passphrase -> UTF-8 bytes
#   $Pass     optional SecureString supplied by the caller (scripting); if absent, prompt without echo
#   -Confirm  prompt a second time and require an exact (case-sensitive) match; used when encrypting so a typo
#             doesn't produce a file nobody can open
# The caller is responsible for zeroing the returned array once the key has been derived.
# -------------------------------------------------------------------------------------------------------------
function Get-PassBytes([securestring]$Pass, [switch]$Confirm) {
    if (-not $Pass) {
        $Pass = Read-Host 'Passphrase' -AsSecureString
        if ($Confirm) {
            $again = Read-Host 'Confirm passphrase' -AsSecureString
            if ((ConvertFrom-SecureString $Pass -AsPlainText) -cne (ConvertFrom-SecureString $again -AsPlainText)) { throw 'Passphrases do not match.' }
        }
    }
    # UTF-8 is used on every platform so the same passphrase derives the same key on Windows, macOS and Linux.
    # Stick to ASCII characters in the passphrase anyway: some OS/IME combinations enter accented characters
    # in different Unicode normal forms, which would give different bytes and therefore a different key.
    $b = [Text.Encoding]::UTF8.GetBytes((ConvertFrom-SecureString $Pass -AsPlainText))
    if ($b.Length -eq 0) { throw 'Empty passphrase.' }
    , $b
}

# PBKDF2-HMAC-SHA256 -> 32-byte AES-256 key. Iterations are stored in the container header so files made with a
# different -Iterations setting still decode. 600 000 is the OWASP 2023 recommendation for PBKDF2-SHA256.
function Get-Key([byte[]]$Pass, [byte[]]$Salt, [int]$Iterations) {
    [Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2($Pass, $Salt, $Iterations, [Security.Cryptography.HashAlgorithmName]::SHA256, 32)
}

# -------------------------------------------------------------------------------------------------------------
# Default output name: camera-style timestamp of the moment of saving, e.g. IMG_20261009_140612_347.png
# (year month day _ hour minute second _ millisecond). Milliseconds keep batch runs unique; if a name is somehow
# taken anyway the clock is bumped forward 1 ms and tried again. Using the save time rather than the source
# name means the image never leaks what it contains ("secrets.png" would).
# -------------------------------------------------------------------------------------------------------------
function New-PixelVaultName([string]$Directory, [string]$Extension, [string]$Prefix = 'IMG_') {
    $t = Get-Date
    do {
        $candidate = Join-Path $Directory ('{0}{1:yyyyMMdd_HHmmss_fff}{2}' -f $Prefix, $t, $Extension)
        $t = $t.AddMilliseconds(1)
    } while (Test-Path -LiteralPath $candidate)
    $candidate
}

# =============================================================================================================
# ConvertTo-PixelVault : file -> PNG container
# =============================================================================================================
function ConvertTo-PixelVault {
    [CmdletBinding()]
    param(
        # Source file. Accepts pipeline input directly or from Get-ChildItem (via the FullName alias).
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)][Alias('FullName')][string]$Path,
        # Explicit output path. When omitted, a timestamp name is generated in the SOURCE file's folder.
        [string]$OutFile,
        # Passphrase as a SecureString, for scripting. When omitted, you are prompted (twice).
        [securestring]$Passphrase,
        # Skip the AES layer. The container is then readable by anyone with this script. Use only when the
        # inner file is already strongly encrypted and you want obfuscation alone.
        [switch]$NoEncryption,
        # Write the PNG as base64 text (.png.b64) instead of binary. ConvertFrom-PixelVault accepts either.
        [switch]$Base64,
        # Prefix for generated names. Ignored when -OutFile is given.
        [string]$NamePrefix = 'IMG_',
        # PBKDF2 iteration count. Higher = slower for you and for an attacker guessing passphrases.
        [ValidateRange(100000, 10000000)][int]$Iterations = 600000,
        # Overwrite an existing output file. Off by default so a batch can't clobber earlier images.
        [switch]$Force
    )
    # Make every .NET exception terminate the function rather than printing a warning and carrying on with
    # half-initialised data. (Without this, an error inside the process block could still let a broken file
    # be written.)
    begin { $ErrorActionPreference = 'Stop' }
    process {
        # ---- read the source file ---------------------------------------------------------------------------
        $src  = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
        $data = [IO.File]::ReadAllBytes($src)
        $name = [Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFileName($src))   # basename only, never the path

        # ---- build the inner payload:  nameLen(2) | name | sha256(32) | data ---------------------------------
        # The SHA-256 lets the decoder prove the restored bytes are identical to the original even in
        # -NoEncryption mode (where there is no GCM tag to rely on).
        $ims = [IO.MemoryStream]::new(); $iw = [IO.BinaryWriter]::new($ims)
        $iw.Write([uint16]$name.Length); $iw.Write($name)
        $iw.Write([Security.Cryptography.SHA256]::HashData($data)); $iw.Write($data); $iw.Flush()
        $inner = $ims.ToArray()

        # ---- per-file random salt and nonce --------------------------------------------------------------------
        # A fresh salt means two files with the same passphrase get different keys; a fresh nonce is mandatory
        # for GCM (reusing a nonce under the same key breaks it completely). Both are zero when not encrypting.
        # The [byte[]] casts matter: PowerShell would otherwise unroll the if-expression into object[].
        $encrypt = -not $NoEncryption
        [byte[]]$salt  = if ($encrypt) { [Security.Cryptography.RandomNumberGenerator]::GetBytes(16) } else { [byte[]]::new(16) }
        [byte[]]$nonce = if ($encrypt) { [Security.Cryptography.RandomNumberGenerator]::GetBytes(12) } else { [byte[]]::new(12) }
        $tag = [byte[]]::new($script:TagLen)                   # filled in by GCM below; stays zero if unencrypted

        # ---- 38-byte header (also the GCM associated data) ---------------------------------------------------
        # BinaryWriter writes little-endian on every platform, which is what Read-LEUInt expects on the way back.
        $hms = [IO.MemoryStream]::new(); $hw = [IO.BinaryWriter]::new($hms)
        $hw.Write([byte]1)                                              # version
        $hw.Write([byte]([int]$encrypt))                                # flags: bit0 = encrypted
        $hw.Write([int32]$(if ($encrypt) { $Iterations } else { 0 }))  # PBKDF2 iterations
        $hw.Write($salt); $hw.Write($nonce)                             # 16 + 12 bytes
        $hw.Write([int32]$inner.Length); $hw.Flush()                    # body length (GCM output = input size)
        $header = $hms.ToArray()

        # ---- encrypt -------------------------------------------------------------------------------------------
        if ($encrypt) {
            $pw  = Get-PassBytes $Passphrase -Confirm
            $key = Get-Key $pw $salt $Iterations
            $body = [byte[]]::new($inner.Length)
            $gcm  = [Security.Cryptography.AesGcm]::new($key, $script:TagLen)
            try   { $gcm.Encrypt($nonce, $inner, $body, $tag, $header) }   # header as AAD -> authenticated
            finally {
                # Zero every sensitive buffer whether or not Encrypt succeeded.
                $gcm.Dispose()
                [Array]::Clear($key, 0, $key.Length)
                [Array]::Clear($pw, 0, $pw.Length)
                [Array]::Clear($inner, 0, $inner.Length)
            }
        } else {
            $body = $inner
        }

        # ---- lay the container into an RGB canvas -------------------------------------------------------------
        # Choose a roughly square image just big enough: 3 bytes per pixel, width = ceil(sqrt(pixels)).
        # The canvas starts as CSPRNG noise so the pixels after the payload are indistinguishable from the
        # ciphertext before it; nobody can see where the data ends.
        $payloadLen = $script:HeaderLen + $script:TagLen + $body.Length
        $pixels   = [math]::Ceiling($payloadLen / 3)
        $width    = [int][math]::Ceiling([math]::Sqrt($pixels))
        $height   = [int][math]::Ceiling($pixels / $width)
        $rowBytes = $width * 3
        $canvas   = [Security.Cryptography.RandomNumberGenerator]::GetBytes($rowBytes * $height)
        [Buffer]::BlockCopy($header, 0, $canvas, 0, $script:HeaderLen)
        [Buffer]::BlockCopy($tag,    0, $canvas, $script:HeaderLen, $script:TagLen)
        [Buffer]::BlockCopy($body,   0, $canvas, $script:HeaderLen + $script:TagLen, $body.Length)

        # ---- PNG scanlines ------------------------------------------------------------------------------------
        # PNG prefixes every row with a 1-byte filter type. We always use 0 (None): the data is random-looking,
        # so the predictive filters would gain nothing, and a fixed filter makes the decoder trivial.
        $raw = [byte[]]::new(($rowBytes + 1) * $height)
        for ($r = 0; $r -lt $height; $r++) {
            [Buffer]::BlockCopy($canvas, $r * $rowBytes, $raw, $r * ($rowBytes + 1) + 1, $rowBytes)   # +1 skips the filter byte (left 0)
        }
        # zlib-wrap the scanlines (PNG requires zlib framing, which ZLibStream provides; DeflateStream would not).
        # Random data does not compress, so the image is about 1.0x the payload size.
        $zms = [IO.MemoryStream]::new()
        $z = [IO.Compression.ZLibStream]::new($zms, [IO.Compression.CompressionLevel]::Optimal, $true)
        $z.Write($raw, 0, $raw.Length); $z.Dispose()                     # Dispose flushes the zlib trailer

        # ---- assemble the PNG -----------------------------------------------------------------------------------
        # IHDR data: width(4) height(4) bitDepth=8 colourType=2(RGB) compression=0 filter=0 interlace=0
        $png = [IO.MemoryStream]::new()
        $png.Write($script:PngSig, 0, 8)
        Write-PngChunk $png 'IHDR' ([byte[]]((Get-BEBytes $width) + (Get-BEBytes $height) + [byte[]](8, 2, 0, 0, 0)))
        Write-PngChunk $png 'IDAT' $zms.ToArray()
        Write-PngChunk $png 'IEND' ([byte[]]::new(0))

        # ---- write the output file --------------------------------------------------------------------------------
        # $dest is a fresh variable per pipeline item; assigning back into $OutFile would make every later item
        # in a batch reuse the first item's generated name.
        $dest = if ($OutFile) { $OutFile } else { New-PixelVaultName ([IO.Path]::GetDirectoryName($src)) $(if ($Base64) { '.png.b64' } else { '.png' }) $NamePrefix }
        $dest = [IO.Path]::GetFullPath($dest, (Get-Location).ProviderPath)   # relative -OutFile is relative to the shell's cwd
        if ((Test-Path -LiteralPath $dest) -and -not $Force) { throw "$dest exists; use -Force to overwrite." }
        if ($Base64) { [IO.File]::WriteAllText($dest, [Convert]::ToBase64String($png.ToArray(), 'InsertLineBreaks')) }   # 76-char lines, email-safe
        else         { [IO.File]::WriteAllBytes($dest, $png.ToArray()) }
        Get-Item -LiteralPath $dest        # return the FileInfo so callers can pipe/inspect it
    }
}

# =============================================================================================================
# ConvertFrom-PixelVault : PNG container -> original file
# =============================================================================================================
function ConvertFrom-PixelVault {
    [CmdletBinding()]
    param(
        # The .png or .png.b64 produced by ConvertTo-PixelVault. Pipeline-friendly like the encoder.
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)][Alias('FullName')][string]$Path,
        # Where to write the restored file. Default: the ORIGINAL filename (stored inside the container),
        # placed in the same folder as the image.
        [string]$OutFile,
        # Passphrase as a SecureString, for scripting. When omitted and the container is encrypted, you are prompted.
        [securestring]$Passphrase,
        # Overwrite an existing destination file.
        [switch]$Force
    )
    begin { $ErrorActionPreference = 'Stop' }
    process {
        # ---- read; accept binary PNG or base64 text transparently --------------------------------------------
        $src   = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
        $bytes = [IO.File]::ReadAllBytes($src)
        $sigHex = [Convert]::ToHexString($script:PngSig)
        if ($bytes.Length -lt 8 -or [Convert]::ToHexString($bytes, 0, 8) -ne $sigHex) {
            # Not a binary PNG: try to interpret the file as base64 text (FromBase64String ignores whitespace/newlines).
            try { $bytes = [Convert]::FromBase64String([IO.File]::ReadAllText($src)) } catch { throw 'Not a PNG or base64-encoded PNG.' }
            if ($bytes.Length -lt 8 -or [Convert]::ToHexString($bytes, 0, 8) -ne $sigHex) { throw 'Base64 content is not a PNG.' }
        }

        # ---- walk the PNG chunks ----------------------------------------------------------------------------------
        # Each chunk: length(4 BE) | type(4) | data(length) | crc(4). We need IHDR (dimensions + format check),
        # every IDAT (concatenated they form one zlib stream) and stop at IEND. Any other chunk types (tEXt, etc.)
        # are skipped; the writer never emits them, but a decoder should tolerate them.
        $pos = 8; $width = 0; $height = 0; $done = $false
        $idat = [IO.MemoryStream]::new()
        while (-not $done -and $pos + 8 -le $bytes.Length) {
            $len  = [int](Read-BEUInt32 $bytes $pos)
            $type = [Text.Encoding]::ASCII.GetString($bytes, $pos + 4, 4)
            $off  = $pos + 8
            if ($off + $len + 4 -gt $bytes.Length) { throw 'Truncated PNG.' }
            switch ($type) {
                'IHDR' {
                    $width = [int](Read-BEUInt32 $bytes $off); $height = [int](Read-BEUInt32 $bytes ($off + 4))
                    # bitDepth must be 8, colourType 2 (RGB), interlace 0. Anything else means the file was
                    # re-encoded by another program (which may also have altered pixel values) or isn't ours.
                    if ($bytes[$off + 8] -ne 8 -or $bytes[$off + 9] -ne 2 -or $bytes[$off + 12] -ne 0) { throw 'Not a PixelVault image (unexpected PNG format; was it re-saved?).' }
                }
                'IDAT' { $idat.Write($bytes, $off, $len) }
                'IEND' { $done = $true }
            }
            $pos = $off + $len + 4     # skip data and CRC (CRC is not re-verified; GCM/SHA-256 below are stronger checks)
        }
        if ($width -le 0 -or $height -le 0) { throw 'Missing IHDR.' }

        # ---- inflate the scanlines --------------------------------------------------------------------------------
        $idat.Position = 0
        $z = [IO.Compression.ZLibStream]::new($idat, [IO.Compression.CompressionMode]::Decompress)
        $rms = [IO.MemoryStream]::new(); $z.CopyTo($rms); $z.Dispose()
        $raw = $rms.ToArray()
        $rowBytes = $width * 3
        if ($raw.Length -lt ($rowBytes + 1) * $height) { throw 'Pixel data truncated.' }

        # ---- strip the per-row filter bytes back out ----------------------------------------------------------------
        $canvas = [byte[]]::new($rowBytes * $height)
        for ($r = 0; $r -lt $height; $r++) {
            $o = $r * ($rowBytes + 1)
            # The writer only ever uses filter 0. A different value means another encoder rewrote the image;
            # undoing other filters is possible but pointless because such a tool may have changed pixels too.
            if ($raw[$o] -ne 0) { throw 'Image uses PNG row filters this tool never writes; it was re-encoded by another program.' }
            [Buffer]::BlockCopy($raw, $o + 1, $canvas, $r * $rowBytes, $rowBytes)
        }

        # ---- parse the container header (offsets per the table in the file header comment) ------------------------
        if ($canvas[0] -ne 1) { throw "Unsupported container version $($canvas[0])." }
        $encrypted = ($canvas[1] -band 1) -eq 1
        $iter    = [int](Read-LEUInt $canvas 2 4)
        $salt    = Get-Slice $canvas 6 16
        $nonce   = Get-Slice $canvas 22 12
        $bodyLen = [int](Read-LEUInt $canvas 34 4)
        $start   = $script:HeaderLen + $script:TagLen          # = 54, where the body begins
        # Smallest valid body: nameLen(2) + 0-byte name + sha256(32) = 34 bytes.
        if ($bodyLen -lt 34 -or $start + $bodyLen -gt $canvas.Length) { throw 'Corrupt container (bad length).' }
        $header = Get-Slice $canvas 0 $script:HeaderLen
        $tag    = Get-Slice $canvas $script:HeaderLen $script:TagLen
        $body   = Get-Slice $canvas $start $bodyLen

        # ---- decrypt ------------------------------------------------------------------------------------------------
        if ($encrypted) {
            # Sanity-bound the iteration count before spending CPU on it: a corrupted/malicious header could
            # otherwise request billions of iterations.
            if ($iter -lt 100000 -or $iter -gt 10000000) { throw 'Corrupt container (bad KDF parameters).' }
            $pw  = Get-PassBytes $Passphrase
            $key = Get-Key $pw $salt $iter
            $inner = [byte[]]::new($bodyLen)
            $gcm = [Security.Cryptography.AesGcm]::new($key, $script:TagLen)
            try     { $gcm.Decrypt($nonce, $body, $tag, $inner, $header) }    # verifies tag over header+body FIRST
            catch   { throw 'Authentication failed: wrong passphrase or image altered.' }   # GCM can't tell which
            finally { $gcm.Dispose(); [Array]::Clear($key, 0, $key.Length); [Array]::Clear($pw, 0, $pw.Length) }
        } else {
            $inner = $body
        }

        # ---- unpack the inner payload:  nameLen(2) | name | sha256(32) | data --------------------------------------
        $nameLen = [int](Read-LEUInt $inner 0 2)
        if (2 + $nameLen + 32 -gt $inner.Length) { throw 'Corrupt payload.' }
        # GetFileName strips any directory components so a crafted container can't write outside the target folder.
        $name = [IO.Path]::GetFileName([Text.Encoding]::UTF8.GetString($inner, 2, $nameLen))
        if ([string]::IsNullOrWhiteSpace($name)) { $name = 'restored.bin' }
        $hash    = Get-Slice $inner (2 + $nameLen) 32
        $dataOff = 2 + $nameLen + 32
        $data    = Get-Slice $inner $dataOff ($inner.Length - $dataOff)
        # Independent end-to-end check of the restored bytes (also the only integrity check in -NoEncryption mode).
        if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($data)) -ne [Convert]::ToHexString($hash)) { throw 'SHA-256 mismatch: payload corrupted.' }

        # ---- write the restored file ---------------------------------------------------------------------------------
        $dest = if ($OutFile) { $OutFile } else { Join-Path ([IO.Path]::GetDirectoryName($src)) $name }
        $dest = [IO.Path]::GetFullPath($dest, (Get-Location).ProviderPath)
        if ((Test-Path -LiteralPath $dest) -and -not $Force) { throw "$dest exists; use -Force to overwrite or -OutFile to redirect." }
        [IO.File]::WriteAllBytes($dest, $data)
        Get-Item -LiteralPath $dest
    }
}

# =============================================================================================================
# Command-line dispatch
#   Runs ONLY when an Action was supplied on the command line. Dot-sourcing the
#   file (no Action) skips this entirely, so the two functions are defined but
#   nothing executes. When an Action IS present we translate it into a call to
#   the matching function, passing the shared parameters by splatting ($common)
#   and the Pack-only switches explicitly. The passphrase (for an encrypted
#   Pack, or any Unpack of an encrypted image) is collected inside the function,
#   never here, so it never appears on this command line or in a process list.
# =============================================================================================================
if ($Action) {
    if (-not $InputPath) { throw "$Action needs an input file." }
    # Parameters common to both functions. -Force is always safe to pass (it is
    # a switch; $false means "don't overwrite").
    $common = @{ Path = $InputPath; Force = $Force }
    if ($OutFile) { $common.OutFile = $OutFile }
    switch ($Action) {
        # -NoEncryption:$NoEncryption forwards the switch's actual state (on or off).
        'Pack'   { ConvertTo-PixelVault @common -NoEncryption:$NoEncryption -Base64:$Base64 -NamePrefix $NamePrefix }
        'Unpack' { ConvertFrom-PixelVault @common }   # Unpack ignores the Pack-only switches
    }
}
