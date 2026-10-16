# =============================================================================
#  lib\GpgTools.Common.ps1
# -----------------------------------------------------------------------------
#  Shared plumbing for every GpgTools engine. This file is NOT runnable on its
#  own: it only defines variables and functions. Each engine dot-sources it,
#  which means "run this file inside MY scope, so its functions and variables
#  become mine":
#
#      . (Join-Path $PSScriptRoot 'lib\GpgTools.Common.ps1')
#      Initialize-GpgTools -BoundParameters $PSBoundParameters -ConfigPath $ConfigPath
#
#  Because of dot-sourcing, every "$script:" reference inside these functions
#  refers to the ENGINE's script scope, not to this file. That is deliberate:
#  the engine can then read $Cfg, $GpgPath, $UseLoopback etc. as plain
#  variables after calling Initialize-GpgTools.
#
#  WHAT LIVES HERE (in file order)
#    1. Constants           - the engines' root folder, the minimum gpg version,
#                             the table of built-in default settings.
#    2. Config loading      - Get-GpgToolsConfigPath, Read-GpgToolsConfig,
#                             Initialize-GpgTools (the one call every engine makes).
#    3. gpg locator         - Get-GpgVersion, Get-GitRoots, Find-Gpg, Resolve-GpgTools.
#                             Finds a usable gpg.exe on PATH, in Gpg4win, or inside
#                             Git for Windows, and decides how the passphrase will
#                             be collected.
#    4. gpg call wrappers   - Read-Passphrase, Invoke-GpgRaw, Invoke-Gpg.
#                             Every gpg invocation in every engine goes through
#                             Invoke-Gpg so passphrase handling is in one place.
#    5. Key helpers         - Format-Fpr, Get-KeyIds, Confirm-MyKey, Export-MyPublicKey.
#    6. File helpers        - New-TempPath, Remove-TempFile, Get-OutputBase,
#                             Resolve-OutputPath.
#
#  CONFIG PRECEDENCE (highest wins)
#    1. a parameter passed on the engine's command line (-MyKeyFingerprint ...)
#    2. the value in GpgTools.config.psd1 (or the file named by -ConfigPath /
#       $env:GPGTOOLS_CONFIG)
#    3. the built-in default in $script:GpgToolsDefaults below
#
#  COMPATIBILITY
#    Runs on Windows PowerShell 5.1 and PowerShell 7+. Nothing here uses a
#    PS7-only API; Import-PowerShellDataFile exists since PS 5.0.
#    Requires GnuPG 2.2+ (the first series that generates Ed25519/Cv25519 keys).
# =============================================================================

# -----------------------------------------------------------------------------
#  1. CONSTANTS
# -----------------------------------------------------------------------------

# Folder that holds the engines: this file lives in <root>\lib, so the parent
# of $PSScriptRoot (the directory of the file currently being dot-sourced) is
# the root. Captured once here because inside a function $PSScriptRoot would
# again be this file's folder, not the engine's.
$script:GpgToolsRoot = Split-Path -Parent $PSScriptRoot

# Oldest gpg we accept. 2.2 is the first series that makes Ed25519/Cv25519
# keys and supports --quick-generate-key / --quick-add-key.
$script:MinGpgVersion = [version]'2.2.0'

# Built-in defaults for every setting the engines know about. Every key here
# may be overridden in the config file or on an engine's command line.
# The config file is validated against this list: a key in the file that is
# NOT here produces a warning (typo protection); a key missing from the file
# silently takes the default. Keep this list and GpgTools.config.psd1 in sync.
$script:GpgToolsDefaults = @{
    # -- Customer exchange (Send / Receive) --
    CustomerPublicKeyPath = 'C:\Keys\customer_pub.asc'            # the customer's public key file (armored or binary)
    CustomerFingerprint   = ''                                    # 40-hex fingerprint from the customer, out-of-band; spaces allowed
    MyKeyFingerprint      = ''                                    # your own key's fingerprint; printed by NewKeyPair / New-GpgKeySet
    MyPrivateKeyPath      = ''                                    # optional backup of your private key; imported if the keyring lacks it
    MyPublicKeyExportPath = 'C:\Keys\my_pub.asc'                  # where ExportPublicKey / NewKeyPair write your public key for the customer
    MyUserId              = 'Your Name <you@company.com>'         # user ID for NewKeyPair; the placeholder is refused on purpose
    KeyAlgorithm          = 'Ed25519'                             # NewKeyPair only: 'Ed25519' (Ed25519 sign + Cv25519 encrypt) or 'RSA4096'
    EncryptToSelf         = $true                                 # Send also encrypts to your key -> enables the full decrypt round-trip check
    OutputNaming          = 'Timestamp'                           # 'Timestamp' = <UTC ISO 8601 basic>.ext ; 'Original' = keep the input stem
    # -- gpg selection and passphrase handling --
    GpgPath               = ''                                    # blank = auto-detect (PATH, Gpg4win, Git for Windows); else full path to gpg.exe
    PassphraseMode        = 'Auto'                                # 'Auto' | 'Pinentry' (gpg's own window) | 'Prompt' (console prompt, loopback)
    # -- Masking (cover text file) --
    MaskedExtension       = '.txt'                                # extension for the whitespace-steg cover file
    # -- Protect/Unprotect: two independent encryption layers --
    InnerFingerprint      = ''                                    # inner (real) key; blank falls back to MyKeyFingerprint
    OuterFingerprint      = ''                                    # outer (decoy-layer) key; must differ from inner for two real layers
    DecoyText             = 'This is a blank placeholder file.'   # what the outer layer decrypts to look like
}

# -----------------------------------------------------------------------------
#  2. CONFIG LOADING
# -----------------------------------------------------------------------------

# Decide which config file to read. Order:
#   1. an explicit path the engine was given (-ConfigPath),
#   2. the GPGTOOLS_CONFIG environment variable (handy for a test config or a
#      second customer without editing the main file),
#   3. GpgTools.config.psd1 next to the engines.
function Get-GpgToolsConfigPath([string]$Explicit) {
    if ($Explicit) { return $Explicit }
    if ($env:GPGTOOLS_CONFIG) { return $env:GPGTOOLS_CONFIG }
    return (Join-Path $script:GpgToolsRoot 'GpgTools.config.psd1')
}

# Read the .psd1. A .psd1 is a PowerShell DATA file: a single hashtable
# literal. Import-PowerShellDataFile parses it in restricted mode and never
# executes code, so a tampered config can at worst supply wrong values, not
# run commands. A missing file is not fatal (the defaults apply) but is
# warned about, because a missing file almost always means a wrong -ConfigPath.
function Read-GpgToolsConfig([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Warning "Config file not found: $Path (using built-in defaults)."
        return @{}
    }
    $h = Import-PowerShellDataFile -LiteralPath $Path
    # Import-PowerShellDataFile returns whatever the file's top-level literal
    # is; anything other than a hashtable means the file is malformed.
    if ($h -isnot [hashtable]) { throw "Config file is not a hashtable: $Path" }
    return $h
}

# The one entry point every engine calls, exactly once, right after
# dot-sourcing this file. It:
#   a) merges defaults <- config file <- command-line parameters into one
#      hashtable and stores it as $script:Cfg (the engine then reads
#      $Cfg.MyKeyFingerprint and so on);
#   b) records which config file was used ($script:ConfigFile) so error
#      messages can tell the user where to fix things;
#   c) resets the per-run passphrase cache;
#   d) unless -NoGpg, locates gpg and chooses the passphrase mode.
#
# -BoundParameters is the engine's $PSBoundParameters: a dictionary holding
# ONLY the parameters the caller actually typed. That is what makes "unset
# means use the config" work: an engine parameter that was not typed is not in
# $PSBoundParameters even though the variable exists with an empty value.
# -NoGpg is for Invoke-MaskedText, which never calls gpg and must not fail on
# a machine without it.
function Initialize-GpgTools {
    param(
        [hashtable]$BoundParameters = @{},
        [string]$ConfigPath,
        [switch]$NoGpg
    )
    $path = Get-GpgToolsConfigPath $ConfigPath
    $file = Read-GpgToolsConfig $path
    $cfg  = @{}
    # Walk the DEFAULTS (not the file) so the result always has every key the
    # engines expect, in the right shape, even with an empty or partial file.
    foreach ($k in $script:GpgToolsDefaults.Keys) {
        $cfg[$k] = $script:GpgToolsDefaults[$k]                                # 3. built-in default
        if ($file.ContainsKey($k))            { $cfg[$k] = $file[$k] }           # 2. config file overrides it
        if ($BoundParameters.ContainsKey($k)) { $cfg[$k] = $BoundParameters[$k] } # 1. command line overrides both
    }
    # Typo protection: a key in the file that no engine knows about is almost
    # certainly a misspelling ("MyKeyFingerPrint") that would otherwise be
    # silently ignored while the engine keeps using the default.
    foreach ($k in $file.Keys) {
        if (-not $script:GpgToolsDefaults.ContainsKey($k)) { Write-Warning "Unknown setting '$k' in $path (ignored)." }
    }
    $script:Cfg        = $cfg
    $script:ConfigFile = $path
    $script:Passphrase = $null      # per-run cache used by Read-Passphrase / Invoke-Gpg (loopback mode)
    if (-not $NoGpg) { Resolve-GpgTools }
    return $cfg
}

# -----------------------------------------------------------------------------
#  3. gpg LOCATOR
#  gpg is never assumed to be on PATH: Windows users often have it only inside
#  Gpg4win or inside Git for Windows. These functions build a list of
#  candidates and pick the first that meets $MinGpgVersion.
# -----------------------------------------------------------------------------

# Run '<gpg> --version', read the first line ("gpg (GnuPG) 2.4.4") and parse
# the "x.y.z" into a [version] so versions can be compared with -ge.
# Returns $null if the path can't be executed or no version can be parsed,
# which Find-Gpg treats as "not a usable candidate".
function Get-GpgVersion([string]$Path) {
    try { $l = & $Path --version 2>$null | Select-Object -First 1 } catch { return $null }
    if ("$l" -match '(\d+)\.(\d+)\.(\d+)') { return [version]"$($Matches[1]).$($Matches[2]).$($Matches[3])" }
    return $null
}

# Find Git-for-Windows install roots, because Git bundles a usable gpg at
# <root>\usr\bin\gpg.exe. Three independent ways, all cheap:
#   * the folder 'git' on PATH lives in (git.exe sits in <root>\cmd, <root>\bin
#     or <root>\mingw64\bin, so walk up to three parents looking for usr\bin\gpg.exe);
#   * the registry keys the Git installer writes (machine-wide and per-user);
#   * the two standard install locations.
# Empty entries are dropped and duplicates collapsed before returning.
function Get-GitRoots {
    $roots = New-Object System.Collections.Generic.List[string]
    $git = Get-Command git -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($git) {
        $d = Split-Path -Parent $git.Source
        foreach ($i in 1..3) {
            $d = Split-Path -Parent $d
            if (-not $d) { break }
            if (Test-Path -LiteralPath (Join-Path $d 'usr\bin\gpg.exe')) { $roots.Add($d); break }
        }
    }
    foreach ($hive in 'HKLM:\SOFTWARE\GitForWindows', 'HKCU:\SOFTWARE\GitForWindows') {
        $p = (Get-ItemProperty -Path $hive -Name InstallPath -ErrorAction SilentlyContinue).InstallPath
        if ($p) { $roots.Add($p) }
    }
    # $env:ProgramFiles / $env:LOCALAPPDATA are empty on non-Windows hosts, so
    # guard against adding a bare "\Git".
    foreach ($p in "$env:ProgramFiles\Git", "$env:LOCALAPPDATA\Programs\Git") { if ($p) { $roots.Add($p) } }
    $roots | Where-Object { $_ } | Select-Object -Unique
}

# Build the ORDERED list of gpg candidates: PATH first (what the user would
# get by typing 'gpg'), then Gpg4win's two possible folders, then each Git
# install's bundled gpg. Each entry records its resolved path, where it came
# from (shown by the Check action) and its version.
# $add is a local scriptblock rather than a function so it can close over
# $found; it de-duplicates by resolved path, since PATH often points at one of
# the other locations.
function Find-Gpg {
    $found = New-Object System.Collections.Generic.List[object]
    $add = {
        param($p, $src)
        if ($p -and (Test-Path -LiteralPath $p)) {
            $full = (Resolve-Path -LiteralPath $p).ProviderPath
            if (-not ($found | Where-Object { $_.Path -eq $full })) {
                $found.Add([pscustomobject]@{ Path = $full; Source = $src; Version = (Get-GpgVersion $full) })
            }
        }
    }
    $onPath = Get-Command gpg -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($onPath) { & $add $onPath.Source 'PATH' }
    & $add "${env:ProgramFiles(x86)}\GnuPG\bin\gpg.exe" 'Gpg4win'
    & $add "$env:ProgramFiles\GnuPG\bin\gpg.exe" 'Gpg4win'
    foreach ($r in Get-GitRoots) { & $add (Join-Path $r 'usr\bin\gpg.exe') "Git ($r)" }
    return $found
}

# Pick the gpg this run will use and decide how the passphrase is collected.
# Sets, in the engine's scope:
#   $GpgPath        - full path to the chosen gpg executable
#   $GpgSource      - 'configured' | 'PATH' | 'Gpg4win' | 'Git (<root>)'
#   $GpgCandidates  - every candidate found (for the Check action's report)
#   $UseLoopback    - $true  = prompt in this console and feed gpg the passphrase on stdin
#                     $false = let gpg open its own pinentry window
# If GpgPath is set in the config it is trusted as-is (no version scan); the
# user chose it on purpose.
function Resolve-GpgTools {
    $script:GpgSource     = 'configured'
    $script:GpgCandidates = @()
    $script:GpgPath       = $script:Cfg.GpgPath
    if (-not $script:GpgPath) {
        $script:GpgCandidates = @(Find-Gpg)
        $pick = $script:GpgCandidates | Where-Object { $_.Version -and $_.Version -ge $script:MinGpgVersion } | Select-Object -First 1
        if ($pick) { $script:GpgPath = $pick.Path; $script:GpgSource = $pick.Source }
    }
    if (-not $script:GpgPath -or -not (Test-Path -LiteralPath $script:GpgPath)) {
        # List what WAS found (e.g. a too-old gpg) so the error is actionable.
        $seen = ($script:GpgCandidates | ForEach-Object { "$($_.Source) v$($_.Version)" }) -join '; '
        throw "No usable gpg $($script:MinGpgVersion)+ found$(if ($seen) { " (found: $seen)" }). Install Git or GnuPG, or set GpgPath in $($script:ConfigFile)."
    }
    # Passphrase mode. 'Auto' chooses loopback ONLY for the MSYS gpg layout
    # (...\usr\bin\gpg.exe = Git for Windows / PortableGit), because that build
    # cannot reliably open a pinentry window from a PowerShell console. Gpg4win
    # and standalone GnuPG get their normal pinentry dialog, so this script
    # never sees the passphrase at all in that case.
    $script:UseLoopback = switch ($script:Cfg.PassphraseMode) {
        'Prompt'   { $true }
        'Pinentry' { $false }
        default    { $script:GpgPath -match '[\\/]usr[\\/]bin[\\/]gpg(\.exe)?$' }
    }
}

# -----------------------------------------------------------------------------
#  4. gpg CALL WRAPPERS
# -----------------------------------------------------------------------------

# Prompt for a passphrase without echo and cache it for the rest of this run
# (loopback mode only), so the user isn't asked again for each gpg call.
# Read-Host -AsSecureString gives a SecureString; NetworkCredential is the
# standard trick to get the plain text back out of it without P/Invoke.
# With -New (key creation) require >= 8 characters and a matching second
# entry so a typo cannot produce a key nobody can unlock.
# The plain text lives only in this process's memory. .NET strings are
# immutable so it cannot be zeroed afterwards; that is a PowerShell
# limitation, not something this script can fix.
function Read-Passphrase([switch]$New) {
    if ($null -ne $script:Passphrase) { return $script:Passphrase }
    $prompt = if ($New) { 'New key passphrase' } else { 'Your key passphrase' }
    $p1 = [Net.NetworkCredential]::new('', (Read-Host -AsSecureString $prompt)).Password
    if ($New) {
        if ($p1.Length -lt 8) { throw "Use a passphrase of at least 8 characters." }
        $p2 = [Net.NetworkCredential]::new('', (Read-Host -AsSecureString 'Repeat passphrase')).Password
        if ($p1 -cne $p2) { throw "Passphrases didn't match." }     # -cne: case-sensitive compare
    }
    $script:Passphrase = $p1
    return $p1
}

# The lowest-level gpg call. Runs gpg with the given argument array, optionally
# piping $StdIn into it (that is how the passphrase travels in loopback mode:
# never on the command line, where Task Manager / process lists could see it).
# Captures stdout AND stderr merged (2>&1) as plain text lines and returns an
# object with the exit code and those lines.
#   * gpg writes its normal status chatter to stderr. Under
#     $ErrorActionPreference = 'Stop' PowerShell would turn that stderr into a
#     terminating error, so the preference is relaxed for the duration of the
#     call and restored in the finally block.
#   * $OutputEncoding controls how PowerShell encodes text it pipes INTO a
#     native program. Setting it to UTF-8 (no BOM) makes a non-ASCII passphrase
#     reach gpg as the same bytes on PS 5.1 (whose default is the OEM code page).
#   * ForEach-Object { "$_" } flattens ErrorRecord objects (from stderr) into
#     strings so later -match tests work uniformly.
function Invoke-GpgRaw([string[]]$GpgArgs, [string]$StdIn) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    try {
        if ($null -ne $StdIn) { $out = $StdIn | & $script:GpgPath @GpgArgs 2>&1 | ForEach-Object { "$_" } }
        else                  { $out = & $script:GpgPath @GpgArgs 2>&1 | ForEach-Object { "$_" } }
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $prev }
    [pscustomobject]@{ ExitCode = $code; Output = @($out) }
}

# The gpg wrapper every engine uses. Three cases:
#   * Calls that don't touch a private key (encrypt, list, import, export of a
#     public key) go straight through Invoke-GpgRaw -- no passphrase involved.
#   * -NeedPass marks calls that DO use a private key (decrypt, key generation,
#     adding a subkey). In PINENTRY mode ($UseLoopback = $false) they also go
#     straight through: gpg pops its own window and this script never sees the
#     passphrase.
#   * -NeedPass in LOOPBACK mode is the interesting path:
#       1. Unless this is a brand-new key, first try the call with
#          '--pinentry-mode cancel'. If gpg-agent still has the passphrase
#          cached from a previous call (default cache: 10 minutes) the command
#          simply succeeds and the user is never prompted. If the agent needs
#          a passphrase the output mentions cancel/pinentry/passphrase and we
#          fall through.
#       2. Prompt (Read-Passphrase, cached after the first time) and re-run
#          with '--pinentry-mode loopback --passphrase-fd 0', feeding the
#          passphrase on stdin. '--batch' suppresses any interactive question.
#       3. On "Bad passphrase" clear the cache and try again, up to three
#          times, then give up.
#   -NewPass means "this is a brand-new key": skip the cache probe (there is
#   nothing cached for a key that doesn't exist yet) and use the confirm-twice
#   prompt from Read-Passphrase -New.
function Invoke-Gpg {
    param([string[]]$GpgArgs, [switch]$NeedPass, [switch]$NewPass)
    if (-not ($NeedPass -and $script:UseLoopback)) { return Invoke-GpgRaw $GpgArgs $null }

    if (-not $NewPass -and $null -eq $script:Passphrase) {
        $try = Invoke-GpgRaw (@('--batch', '--pinentry-mode', 'cancel') + $GpgArgs) $null
        if (($try.Output -join "`n") -notmatch 'cancel|No secret key|passphrase|pinentry') { return $try }
    }
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $pw = Read-Passphrase -New:$NewPass
        $r = Invoke-GpgRaw (@('--batch', '--pinentry-mode', 'loopback', '--passphrase-fd', '0') + $GpgArgs) $pw
        if (($r.Output -join "`n") -notmatch 'Bad passphrase') { return $r }
        $script:Passphrase = $null
        Write-Warning "Bad passphrase."
    }
    throw "Bad passphrase 3 times; giving up."
}

# -----------------------------------------------------------------------------
#  5. KEY HELPERS
# -----------------------------------------------------------------------------

# Normalize a fingerprint for comparison: strip every whitespace character
# (people paste "4062 CEF0 0A4E ..." with spaces) and upper-case it (gpg
# prints upper-case hex; some tools print lower-case).
function Format-Fpr([string]$f) { ($f -replace '\s', '').ToUpperInvariant() }

# Return every 16-hex key ID -- primary AND subkeys -- belonging to a
# fingerprint. Read from gpg's --with-colons output, which is the stable,
# machine-readable format (the human format changes between versions).
# Record types: pub/sub = public primary/subkey, sec/ssb = secret primary/
# subkey. Field index 4 (0-based) of each record is the key ID.
# -Secret lists the private keyring instead of the public one; used to check
# "do I actually have the secret key for this fingerprint?".
# Why key IDs and not fingerprints: an encrypted file's packets name the
# recipient SUBKEY by its 16-hex key ID, so matching a file to a key means
# matching against the set of all its key IDs.
function Get-KeyIds([string]$Fpr, [switch]$Secret) {
    $list = if ($Secret) { '--list-secret-keys' } else { '--list-keys' }
    @((Invoke-Gpg @('--batch', '--with-colons', $list, $Fpr)).Output |
        Where-Object { $_ -match '^(pub|sub|sec|ssb):' } |
        ForEach-Object { $_.Split(':')[4].ToUpperInvariant() })
}

# Ensure YOUR private key is available in the keyring (needed to decrypt, to
# add subkeys, to export). If the keyring lacks it and MyPrivateKeyPath is
# set, import it from that backup file and verify the fingerprint now matches
# (a wrong backup file would otherwise import some OTHER key and the later
# decrypt would fail with a confusing message).
# Returns the normalized fingerprint for callers to use.
function Confirm-MyKey {
    if (-not $script:Cfg.MyKeyFingerprint) { throw "Set MyKeyFingerprint in $($script:ConfigFile) (run NewKeyPair first if you have no key)." }
    $fpr = Format-Fpr $script:Cfg.MyKeyFingerprint
    if ((Get-KeyIds $fpr -Secret).Count -eq 0) {
        if (-not $script:Cfg.MyPrivateKeyPath) { throw "Your private key $fpr is not in the keyring and MyPrivateKeyPath is not set." }
        $imp = Invoke-Gpg @('--import', (Resolve-Path -LiteralPath $script:Cfg.MyPrivateKeyPath).ProviderPath)
        if ($imp.ExitCode -ne 0 -or (Get-KeyIds $fpr -Secret).Count -eq 0) {
            throw "Importing your private key failed or fingerprint doesn't match:`n$($imp.Output -join "`n")"
        }
    }
    return $fpr
}

# Write your PUBLIC key to MyPublicKeyExportPath as an ASCII-armored .asc
# (the file you hand to the customer; safe to email). Creates the target
# folder if needed. --yes lets gpg overwrite an existing file, which is the
# point of ExportPublicKey ("the customer lost it, write it again").
function Export-MyPublicKey([string]$Fpr) {
    $dest = $script:Cfg.MyPublicKeyExportPath
    $dir = Split-Path -Parent $dest
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    $exp = Invoke-Gpg @('--batch', '--yes', '--armor', '--output', $dest, '--export', $Fpr)
    if ($exp.ExitCode -ne 0 -or -not (Test-Path $dest)) { throw "Public key export failed:`n$($exp.Output -join "`n")" }
}

# -----------------------------------------------------------------------------
#  6. FILE HELPERS
# -----------------------------------------------------------------------------

# Delete a temp file if it exists. Used in every engine's finally block so
# intermediate plaintext/ciphertext never outlives the run, even on error.
function Remove-TempFile([string]$Path) { if ($Path -and (Test-Path -LiteralPath $Path)) { Remove-Item -LiteralPath $Path -Force } }

# A unique temp file path (random GUID name, caller-chosen extension) in the
# OS temp folder. The file is NOT created here; gpg or File.WriteAllBytes
# creates it. GUID names cannot collide with a parallel run.
function New-TempPath([string]$Ext) { Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N') + $Ext) }

# The base (extension-less) name for an output file, per the OutputNaming
# setting:
#   'Timestamp' -> current UTC time in ISO 8601 BASIC format, e.g. 20261015T184500Z.
#                  Basic format has no colons (Windows forbids them in file
#                  names) and sorts chronologically. Using the time instead of
#                  the input name means the output never leaks what it contains.
#   'Original'  -> the input file's name without its extension.
function Get-OutputBase([string]$InFile) {
    if ($script:Cfg.OutputNaming -eq 'Timestamp') { return [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') }
    return [System.IO.Path]::GetFileNameWithoutExtension($InFile)
}

# Turn an engine's optional -OutputPath into a concrete file path:
#   * blank           -> <input file's folder>\<DefaultName>
#   * an existing dir -> <that dir>\<DefaultName>
#   * anything else   -> used as given
# and REFUSE to overwrite an existing file. Every engine writes through this,
# so "never clobber" is enforced in one place. (gpg's own --yes is still
# passed on the encrypt calls because the path has already been checked here.)
function Resolve-OutputPath([string]$Requested, [string]$InFile, [string]$DefaultName) {
    $out = $Requested
    if (-not $out) { $out = Join-Path (Split-Path -Parent $InFile) $DefaultName }
    elseif (Test-Path -LiteralPath $out -PathType Container) { $out = Join-Path $out $DefaultName }
    if (Test-Path -LiteralPath $out) { throw "Output already exists: $out" }
    return $out
}
