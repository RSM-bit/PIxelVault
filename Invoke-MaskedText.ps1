# =============================================================================
#  Invoke-MaskedText.ps1  --  Mask / Unmask engine
# -----------------------------------------------------------------------------
#  Wrap any file (normally a PGP .asc) in a cover text file whose only visible
#  content is one innocuous sentence, or recover the bytes from such a cover.
#  NO gpg is involved, so this is the one engine that runs on a machine with no
#  GnuPG installed. The format and the "obfuscation, not security" caveat live
#  in lib\GpgTools.MaskedText.ps1.
#
#  USAGE
#      .\Invoke-MaskedText.ps1 Mask   .\file.asc              # -> <timestamp>.txt next to the input
#      .\Invoke-MaskedText.ps1 Unmask .\20261015T184500Z.txt  # -> <stem>.asc
#      .\Invoke-MaskedText.ps1 Mask .\file.asc -OutputPath D:\cover.txt
#
#  SETTINGS USED FROM GpgTools.config.psd1
#      MaskedExtension, OutputNaming
#  (either can be overridden for one run with the matching -parameter.)
#
#  Runs on Windows PowerShell 5.1 and PowerShell 7+.
# =============================================================================
[CmdletBinding()]
param(
    # $Action is positional #0 and restricted to these two names; PowerShell
    # rejects anything else before the script body runs.
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('Mask', 'Unmask')][string]$Action,
    # $InputPath is positional #1: the file to mask, or the cover to unmask.
    [Parameter(Mandatory = $true, Position = 1)][string]$InputPath,
    # Optional explicit output; blank lets the engine auto-name (see below).
    [string]$OutputPath,
    # Point at a non-default config file (also honoured: $env:GPGTOOLS_CONFIG).
    [string]$ConfigPath,
    # -- per-run overrides of config values; leave unset to use the config file --
    [string]$MaskedExtension,
    [ValidateSet('Timestamp', 'Original')][string]$OutputNaming
)
# Stop on the first unhandled error so a failure never silently continues.
$ErrorActionPreference = 'Stop'

# Load the shared library and the masking functions (both live in .\lib).
. (Join-Path $PSScriptRoot 'lib\GpgTools.Common.ps1')
. (Join-Path $PSScriptRoot 'lib\GpgTools.MaskedText.ps1')

# Merge defaults <- config file <- the -parameters actually typed into $Cfg.
# -NoGpg because masking never calls gpg and must work with none installed.
# $PSBoundParameters holds only the parameters the caller actually passed, so
# an untyped override falls through to the config value.
$null = Initialize-GpgTools -BoundParameters $PSBoundParameters -ConfigPath $ConfigPath -NoGpg

# Resolve the input to a full, provider-free path up front (also validates it exists).
$inFile = (Resolve-Path -LiteralPath $InputPath).ProviderPath

switch ($Action) {

    'Mask' {
        # Auto-name: <timestamp-or-stem><MaskedExtension> in the input's folder,
        # unless -OutputPath overrides. Resolve-OutputPath refuses to overwrite.
        $out = Resolve-OutputPath $OutputPath $inFile ((Get-OutputBase $inFile) + $Cfg.MaskedExtension)
        # Read the whole source file as bytes and wrap it, verifying the cover
        # unmasks back to the identical bytes before reporting success.
        $src = [System.IO.File]::ReadAllBytes($inFile)
        $kib = Write-MaskedTextVerified -Payload $src -OutPath $out
        # Emit a result object; the menu prints it as a list.
        [pscustomobject]@{
            Output      = $out
            StatedKiB   = $kib
            OutputBytes = (Get-Item -LiteralPath $out).Length
            VisibleLine = "This is a blank file that is exactly $kib."
            RoundTrip   = 'OK'
        }
    }

    'Unmask' {
        # A friendly heads-up if the file's first line doesn't match the cover
        # sentence; still attempt it, since the user chose this file on purpose.
        if (-not (Test-MaskedText $inFile)) { Write-Warning "First line doesn't look like a masked cover; trying anyway." }
        # Recovered files default to <stem>.asc (the usual masked payload), in
        # the cover's folder, unless -OutputPath overrides.
        $stem = [System.IO.Path]::GetFileNameWithoutExtension($inFile)
        $out  = Resolve-OutputPath $OutputPath $inFile ($stem + '.asc')
        [System.IO.File]::WriteAllBytes($out, (ConvertFrom-MaskedText -InPath $inFile))
        [pscustomobject]@{ Output = $out; OutputBytes = (Get-Item -LiteralPath $out).Length }
    }
}
