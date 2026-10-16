#Requires -Version 7
<#
===============================================================================================================
 New-GpgKeySet.ps1
===============================================================================================================

.SYNOPSIS
  Create an OpenPGP key set in the "offline primary" layout: a certify-only Ed25519 primary key plus separate
  sign / encrypt / authenticate subkeys, exported as a complete set of backup files into one folder.

.DESCRIPTION
  WHY THIS LAYOUT
    The primary key is the identity. It is only ever used to certify (create/renew subkeys, sign other people's
    keys). Day-to-day work (signing, decrypting, SSH auth) is done by subkeys. If a laptop holding only the
    subkeys is compromised, you revoke those subkeys with the primary and issue new ones; the identity and the
    trust other people have placed in it survive. With -RemovePrimary the primary's secret half is deleted from
    the working keyring after export, so it exists only in the secret-FULL backup file.

  WHY ED25519 / CV25519 (NO RSA)
    ROCA was a flaw in how certain chips generated RSA keys. Curve25519 keys are not affected by it, are
    generated here in software by GnuPG (not on a smartcard), and are small and fast. Nothing in this script
    uses RSA.

  RUN IT ON YOUR OWN MACHINE
    Ideally one that is offline while the keys are generated, or a Tails/live-USB session. The script itself
    makes no network connections.

  PASSPHRASE HANDLING (the "type it once" design)
    gpg normally asks for the passphrase through its pinentry dialog at every step that touches a secret key:
    creating the primary, each of three subkey additions, two secret exports... up to ten prompts. Instead:
      1. The passphrase is asked ONCE here (and confirmed), without echo, as a SecureString.
      2. It is held only in this process's memory for the duration of the run.
      3. It is handed to every gpg step over stdin with  --pinentry-mode loopback --passphrase-fd 0
         (fd 0 = standard input). It is never put on the command line (visible in process lists), never
         written to a file, never logged.
      4. The primary key and every subkey therefore share the same passphrase, and both secret backup files
         open with it.
      5. In the finally block the variable is cleared and the keyring's gpg-agent is killed so no cached copy
         outlives the run.
    .NET strings are immutable, so the plaintext copy can't be truly zeroed in memory; this is a PowerShell
    limitation, acceptable for a one-shot run on your own machine.
    -Pinentry switches back to gpg's own prompt at each step (the script then never sees the passphrase).
    -Passphrase accepts a SecureString for scripted/unattended use.

  STORAGE (-Storage)
    Removable (default)
      -OutDir defaults to <removable drive>\gpg-keys. The keyring (-GnuPGHome) defaults to <OutDir>\gnupg, an
      isolated keyring ON THE STICK, so the machine's own ~/.gnupg is never touched and nothing secret is left
      on the computer when you eject. Removable-drive detection and the "is this path really removable" check
      use WMI (Win32_LogicalDisk DriveType=2) and are therefore Windows-only; on macOS/Linux the script warns
      and trusts the -OutDir you give it. Fails if no removable drive is present; asks you to choose with
      -OutDir if several are.
    Local
      -OutDir defaults to ~\gpg-keys. The machine's normal keyring is used unless -GnuPGHome is given.

  NEVER OVERWRITES
    Before doing anything the script lists every key set already in OutDir (by reading each *.public.asc) and
    refuses to proceed if one already carries the same email address, unless -AllowDuplicateEmail is given. The
    keyring is checked the same way. Every output file is tested for existence immediately before being
    written. Output names start with the new key's fingerprint, which is unique per key.

  OUTPUT FILES (all in OutDir, FPR = 40-hex-char fingerprint of the new primary key)
    FPR.public.asc           Public key, minimal export. The ONLY file you distribute (keyserver, WKD, GitHub).
    FPR.secret-FULL.asc      Primary + all subkeys, passphrase-protected. The master backup. Two offline USB
                             sticks in different places, or paper. NEVER cloud storage, not even inside a
                             PixelVault image.
    FPR.secret-subkeys.asc   Subkeys only (the primary appears as a stub). What you import on everyday machines.
    FPR.revoke.asc           Revocation certificate, ready to import. Anyone holding it can kill the key, so
                             store it apart from secret-FULL (ideally a different place/medium).
    FPR.fingerprint.txt      The fingerprint grouped in fours, for printing, reading aloud, email signatures.

  EXPIRY
    Primary 5 years, subkeys 2 years by default. Both can be extended later with the primary key (gpg
    --quick-set-expire). Expiry is a dead-man switch for a key you lose control of, not a hard end date.

.PARAMETER Name
  Real name for the user ID, e.g. 'Bear Sunderland'.
.PARAMETER Email
  Email for the user ID. People look the key up by this; for WKD it must be on a domain you control.
.PARAMETER Storage
  'Removable' (default) or 'Local'. See STORAGE above.
.PARAMETER OutDir
  Folder for the output files. Defaults depend on -Storage.
.PARAMETER GnuPGHome
  Keyring directory to use. Defaults: Removable -> <OutDir>\gnupg; Local -> gpg's normal home.
.PARAMETER Comment
  Optional comment in the user ID: "Name (Comment) <email>". Usually leave empty.
.PARAMETER PrimaryExpire
  gpg expiry spec for the primary key: '5y', '0' (never), '2027-01-01', etc.
.PARAMETER SubkeyExpire
  gpg expiry spec for the three subkeys.
.PARAMETER RemovePrimary
  After export, delete the primary's secret key from the keyring, keeping only the subkeys.
.PARAMETER Pinentry
  Let gpg prompt for the passphrase itself at every step; the script never handles it.
.PARAMETER Passphrase
  Supply the passphrase as a SecureString instead of being prompted. Cannot be combined with -Pinentry.
.PARAMETER AllowDuplicateEmail
  Create a key even though OutDir or the keyring already holds one for this email.

.EXAMPLE
  .\New-GpgKeySet.ps1 -Name 'Bear Sunderland' -Email 'you@example.com'
    # Windows: USB stick auto-detected, keys and keyring written to E:\gpg-keys, one passphrase prompt.
.EXAMPLE
  .\New-GpgKeySet.ps1 -Name 'Bear Sunderland' -Email 'you@example.com' -Storage Local -RemovePrimary
    # Use the machine's own keyring, write backups to ~\gpg-keys, then strip the primary from the keyring.
.EXAMPLE
  .\New-GpgKeySet.ps1 -Name 'Bear Sunderland' -Email 'you@example.com' -OutDir E:\keys -Pinentry
    # Explicit folder on the stick; gpg prompts at each step instead of the script.
.EXAMPLE
  $p = Read-Host 'Passphrase' -AsSecureString
  .\New-GpgKeySet.ps1 -Name 'Bear Sunderland' -Email 'you@example.com' -Passphrase $p
    # Scripted: passphrase read elsewhere and passed in.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Name,
    # Loose email check: something@something.tld with no spaces or angle brackets (gpg needs the <> it adds itself).
    [Parameter(Mandatory)][ValidatePattern('^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$')][string]$Email,
    [ValidateSet('Removable', 'Local')][string]$Storage = 'Removable',
    [string]$OutDir,
    [string]$GnuPGHome,
    [string]$Comment,
    [string]$PrimaryExpire = '5y',
    [string]$SubkeyExpire  = '2y',
    [switch]$RemovePrimary,
    [switch]$Pinentry,
    [securestring]$Passphrase,
    [switch]$AllowDuplicateEmail
)
# Any error terminates the script. Half-finished key generation is worse than none.
$ErrorActionPreference = 'Stop'
# $IsWindows is an automatic variable in PowerShell 7 (absent in 5.1, which the #Requires line already excludes).
$isWin = $IsWindows

# -------------------------------------------------------------------------------------------------------------
# Locate gpg and check its version
# 2.4 is end-of-life; 2.5 is current. Anything older than 2.4 is refused because the --quick-* commands and
# loopback pinentry behaviour this script relies on are not reliable there.
# -------------------------------------------------------------------------------------------------------------
$gpg = (Get-Command gpg -ErrorAction SilentlyContinue).Source
if (-not $gpg) { throw 'gpg not found. Install GnuPG 2.5.x (Windows: Gpg4win, then the GnuPG 2.5 installer on top).' }
$verLine = (& $gpg --version | Select-Object -First 1)          # e.g. "gpg (GnuPG) 2.5.22"
if ($verLine -match '(\d+)\.(\d+)\.(\d+)') {
    $v = [version]"$($Matches[1]).$($Matches[2]).$($Matches[3])"
    if ($v -lt [version]'2.4.0') { throw "$verLine is too old; install GnuPG 2.5.x." }
    if ($v -lt [version]'2.5.0') { Write-Warning "$verLine works, but the 2.4 branch is end-of-life. Upgrade to 2.5.x." }
}

# -------------------------------------------------------------------------------------------------------------
# Removable-drive helpers (Windows only; see STORAGE in the header)
# -------------------------------------------------------------------------------------------------------------

# Returns drive roots like 'E:\' for every drive Windows classes as removable (DriveType 2 = USB sticks, SD
# cards; USB *hard disks* often report as fixed (3) and would need -Storage Local or an explicit -OutDir).
function Get-RemovableRoots {
    if ($isWin) { (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' | ForEach-Object { $_.DeviceID + '\' }) }
    else { @() }
}

# $true / $false on Windows; $null (= "can't tell") elsewhere so the caller can warn instead of refusing.
function Test-OnRemovable([string]$Path) {
    if (-not $isWin) { return $null }
    $root = [IO.Path]::GetPathRoot($Path)
    [bool](Get-RemovableRoots | Where-Object { $_ -ieq $root })
}

# -------------------------------------------------------------------------------------------------------------
# Resolve OutDir and GnuPGHome according to -Storage
# -------------------------------------------------------------------------------------------------------------
if ($Storage -eq 'Removable') {
    if (-not $OutDir) {
        $roots = @(Get-RemovableRoots)
        if (-not $isWin) { throw 'Removable-drive detection is Windows-only; pass -OutDir pointing at the mounted drive.' }
        if ($roots.Count -eq 0) { throw 'No removable drive found. Insert the USB stick, or use -Storage Local.' }
        if ($roots.Count -gt 1) { throw "Several removable drives present ($($roots -join ', ')); pass -OutDir to pick one." }
        $OutDir = Join-Path $roots[0] 'gpg-keys'
    }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null           # -Force: no error if it already exists
    $OutDir = (Resolve-Path -LiteralPath $OutDir).ProviderPath             # absolute, provider-free path
    switch (Test-OnRemovable $OutDir) {
        $false { throw "$OutDir is not on a removable drive. Use -Storage Local if that is intended." }
        $null  { Write-Warning "Cannot confirm $OutDir is removable on this OS; proceeding." }
    }
    # Isolated keyring on the stick unless the caller chose one explicitly.
    if (-not $GnuPGHome) { $GnuPGHome = Join-Path $OutDir 'gnupg' }
} else {
    if (-not $OutDir) { $OutDir = Join-Path $HOME 'gpg-keys' }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $OutDir = (Resolve-Path -LiteralPath $OutDir).ProviderPath
}

# $gpgArgsBase is prepended to every gpg call so the --homedir choice is applied consistently.
$gpgArgsBase = @()
if ($GnuPGHome) {
    New-Item -ItemType Directory -Force -Path $GnuPGHome | Out-Null
    $GnuPGHome = (Resolve-Path -LiteralPath $GnuPGHome).ProviderPath
    # gpg complains about "unsafe permissions" on a world-readable homedir on Unix; irrelevant on Windows.
    if (-not $isWin) { chmod 700 $GnuPGHome }
    $gpgArgsBase += @('--homedir', $GnuPGHome)
}
Write-Host "Storage: $Storage   OutDir: $OutDir   Keyring: $(if ($GnuPGHome) { $GnuPGHome } else { 'default' })" -ForegroundColor Cyan

# -------------------------------------------------------------------------------------------------------------
# Inventory of key sets already in OutDir, and refusal to duplicate an email
# Each *.public.asc is parsed with --show-keys (which reads a key file without importing it). --with-colons
# gives machine-readable output: "fpr:::::::::<FINGERPRINT>:" and "uid:...:<User ID>:" records, where the
# payload is field index 9 after splitting on ':'.
# -------------------------------------------------------------------------------------------------------------
$existingSets = foreach ($f in Get-ChildItem -LiteralPath $OutDir -Filter '*.public.asc' -ErrorAction SilentlyContinue) {
    $cols = & $gpg --batch --with-colons --show-keys $f.FullName 2>$null
    $fp = ($cols | Where-Object { $_ -like 'fpr:*' } | Select-Object -First 1)     # first fpr = primary key
    $u  = ($cols | Where-Object { $_ -like 'uid:*' } | Select-Object -First 1)
    if ($fp) { [pscustomobject]@{ Fingerprint = $fp.Split(':')[9]; Uid = $(if ($u) { $u.Split(':')[9] } else { '?' }); File = $f.Name } }
}
if ($existingSets) {
    Write-Host "Existing key sets in $OutDir (left untouched):" -ForegroundColor Yellow
    $existingSets | ForEach-Object { Write-Host "  $($_.Fingerprint)  $($_.Uid)" }
    $same = $existingSets | Where-Object { $_.Uid -like "*<$Email>*" }
    if ($same -and -not $AllowDuplicateEmail) {
        throw "A key set for <$Email> already exists here ($($same.Fingerprint -join ', ')). Nothing was changed. Use -AllowDuplicateEmail to create another alongside it."
    }
}
# Same test against the keyring itself. "<email>" in angle brackets makes gpg match the email exactly rather
# than as a substring of the whole user ID.
$existingRing = & $gpg @gpgArgsBase --batch --list-keys --with-colons -- "<$Email>" 2>$null
if ($LASTEXITCODE -eq 0 -and $existingRing -and -not $AllowDuplicateEmail) {
    throw "The keyring already holds a key for <$Email>. Use -GnuPGHome for a clean keyring, -AllowDuplicateEmail, or remove the old key first."
}

# -------------------------------------------------------------------------------------------------------------
# Passphrase: collect once (see PASSPHRASE HANDLING in the header)
# $passPlain holds the plaintext for the rest of the run and is cleared in the finally block below.
# Minimum 12 characters is a floor, not a recommendation; aim for 6+ random words.
# -------------------------------------------------------------------------------------------------------------
$passPlain = $null
if ($Pinentry -and $Passphrase) { throw 'Use -Pinentry or -Passphrase, not both.' }
if ($Passphrase) {
    $passPlain = ConvertFrom-SecureString $Passphrase -AsPlainText
    if ($passPlain.Length -lt 12) { throw 'Passphrase too short (12+ characters).' }
} elseif (-not $Pinentry) {
    Write-Host 'Choose a passphrase (6+ random words). It protects the primary key, all subkeys, and every backup file.' -ForegroundColor Yellow
    do {
        $p1 = Read-Host 'Passphrase' -AsSecureString          # -AsSecureString: no echo to the console
        $p2 = Read-Host 'Confirm   ' -AsSecureString
        $a = ConvertFrom-SecureString $p1 -AsPlainText; $b = ConvertFrom-SecureString $p2 -AsPlainText
        $ok = ($a.Length -ge 12) -and ($a -ceq $b)              # -ceq: case-sensitive comparison
        if (-not $ok) { Write-Host ($(if ($a.Length -lt 12) { 'Too short (12+ characters).' } else { 'Passphrases do not match.' })) -ForegroundColor Red }
    } until ($ok)
    $passPlain = $a; $b = $null
}

# -------------------------------------------------------------------------------------------------------------
# Invoke-Gpg: run gpg with the common arguments, fail loudly on non-zero exit
#   -NeedsPass  this step must unlock or protect a secret key. Unless -Pinentry was chosen, the passphrase is
#               piped to gpg's stdin and gpg is told to read it from there:
#                 --pinentry-mode loopback   don't open a pinentry dialog; take the passphrase from the caller
#                 --passphrase-fd 0          read it from file descriptor 0 (stdin), terminated by newline
#               Piping a string to a native command in PowerShell writes it to stdin followed by a newline,
#               which is exactly what gpg expects.
#   --batch     always on: never ask interactive questions; fail instead of hanging.
# -------------------------------------------------------------------------------------------------------------
function Invoke-Gpg {
    param([switch]$NeedsPass, [Parameter(ValueFromRemainingArguments)][string[]]$GpgArgs)
    if ($NeedsPass -and -not $Pinentry) {
        $out = $passPlain | & $gpg @gpgArgsBase --batch --pinentry-mode loopback --passphrase-fd 0 @GpgArgs
    } else {
        $out = & $gpg @gpgArgsBase --batch @GpgArgs
    }
    if ($LASTEXITCODE -ne 0) { throw "gpg $($GpgArgs -join ' ') failed (exit $LASTEXITCODE)." }
    $out
}

# Guard used before every file write. Fingerprint-prefixed names make a clash practically impossible, but the
# check costs nothing and turns "impossible" into "guaranteed".
function Assert-Fresh([string]$Path) { if (Test-Path -LiteralPath $Path) { throw "Refusing to overwrite existing file: $Path" } }

# The try/finally guarantees the passphrase is cleared and the agent killed even if a gpg step fails midway.
try {
    # ---------------------------------------------------------------------------------------------------------
    # 1. Primary key: Ed25519, usage "cert" only
    #    --quick-generate-key <uid> <algo> <usage> <expire> is the non-interactive form of --full-generate-key.
    #    The "--" stops gpg from treating a user ID that starts with "-" as an option.
    # ---------------------------------------------------------------------------------------------------------
    $uid = if ($Comment) { "$Name ($Comment) <$Email>" } else { "$Name <$Email>" }
    Write-Host "Creating certify-only Ed25519 primary for: $uid" -ForegroundColor Cyan
    if ($Pinentry) { Write-Host 'gpg will prompt for the passphrase at each step.' -ForegroundColor Yellow }

    # Identify the NEW key by diffing the keyring's secret-key fingerprints before and after generation. Looking
    # it up by email instead would be ambiguous when -AllowDuplicateEmail puts two keys for one email in the ring.
    $before = @(& $gpg @gpgArgsBase --batch --list-secret-keys --with-colons 2>$null | Where-Object { $_ -like 'fpr:*' } | ForEach-Object { $_.Split(':')[9] })
    Invoke-Gpg -NeedsPass --quick-generate-key -- $uid ed25519 cert $PrimaryExpire | Out-Null
    $after = @(Invoke-Gpg --list-secret-keys --with-colons | Where-Object { $_ -like 'fpr:*' } | ForEach-Object { $_.Split(':')[9] })
    $fpr = ($after | Where-Object { $_ -notin $before } | Select-Object -First 1)
    # v4 keys have 40-hex fingerprints (SHA-1); v5/v6 keys have 64 (SHA-256). Accept both.
    if ($fpr -notmatch '^[0-9A-F]{40}$|^[0-9A-F]{64}$') { throw "Could not identify the new key's fingerprint." }

    # ---------------------------------------------------------------------------------------------------------
    # 2. Subkeys: --quick-add-key <fpr> <algo> <usage> <expire>
    #    ed25519 for signing and authentication (signature algorithm), cv25519 (X25519) for encryption
    #    (key-agreement algorithm). Each unlocks the primary, which is why each needs the passphrase. New
    #    subkeys inherit the primary's passphrase.
    # ---------------------------------------------------------------------------------------------------------
    Write-Host 'Adding subkeys: ed25519 sign, cv25519 encrypt, ed25519 auth' -ForegroundColor Cyan
    Invoke-Gpg -NeedsPass --quick-add-key $fpr ed25519 sign $SubkeyExpire | Out-Null
    Invoke-Gpg -NeedsPass --quick-add-key $fpr cv25519 encr $SubkeyExpire | Out-Null
    Invoke-Gpg -NeedsPass --quick-add-key $fpr ed25519 auth $SubkeyExpire | Out-Null

    # ---------------------------------------------------------------------------------------------------------
    # 3. Exports
    # ---------------------------------------------------------------------------------------------------------
    $pub  = Join-Path $OutDir "$fpr.public.asc"
    $full = Join-Path $OutDir "$fpr.secret-FULL.asc"
    $subs = Join-Path $OutDir "$fpr.secret-subkeys.asc"
    $rev  = Join-Path $OutDir "$fpr.revoke.asc"
    $fpt  = Join-Path $OutDir "$fpr.fingerprint.txt"
    $pub, $full, $subs, $rev, $fpt | ForEach-Object { Assert-Fresh $_ }

    # --armor: ASCII text (.asc) instead of binary, so the files survive email/paper/copy-paste.
    # export-minimal: drop third-party signatures on the public key (none yet, but keeps the published file small).
    Invoke-Gpg --armor --export-options export-minimal --output $pub --export $fpr | Out-Null
    # Secret exports re-encrypt the key material for the file, so gpg needs the passphrase again (NeedsPass).
    Invoke-Gpg -NeedsPass --armor --output $full --export-secret-keys $fpr | Out-Null
    Invoke-Gpg -NeedsPass --armor --output $subs --export-secret-subkeys $fpr | Out-Null

    # Revocation certificate: gpg writes one automatically at key creation into <homedir>/openpgp-revocs.d/.
    # It is stored with ':' prefixed to the "-----BEGIN" line so an accidental import does nothing; the prefix
    # is stripped here so the copy in OutDir is ready to use in an emergency (gpg --import FPR.revoke.asc, then
    # publish the revoked public key).
    $home_ = if ($GnuPGHome) { $GnuPGHome } else { (& gpgconf --list-dirs homedir) }
    $autoRev = Join-Path $home_ "openpgp-revocs.d/$fpr.rev"
    if (Test-Path -LiteralPath $autoRev) {
        (Get-Content -LiteralPath $autoRev -Raw) -replace '(?m)^:-----BEGIN', '-----BEGIN' | Set-Content -LiteralPath $rev -NoNewline
    } else {
        Write-Warning "Auto revocation certificate not found at $autoRev. Create one manually: gpg --gen-revoke $fpr"
    }

    # Fingerprint grouped in fours: "4062 CEF0 0A4E ..." is how gpg --fingerprint prints it and how people
    # read it aloud. The -split on a capture group yields the groups interleaved with empty strings; the
    # Where-Object drops the empties.
    $grouped = (($fpr -split '(.{4})' | Where-Object { $_ }) -join ' ')
    @"
OpenPGP key: $uid
Fingerprint: $grouped
Created:     $(Get-Date -Format 'yyyy-MM-dd')
"@ | Set-Content -LiteralPath $fpt

    # ---------------------------------------------------------------------------------------------------------
    # 4. Optionally strip the primary secret key from the keyring
    #    "FPR!" (trailing !) tells --delete-secret-keys to delete exactly that key and not its subkeys.
    #    Afterwards --list-secret-keys shows "sec#" (field 15 = '#') meaning "secret part not available".
    # ---------------------------------------------------------------------------------------------------------
    if ($RemovePrimary) {
        Write-Host 'Removing the primary secret key from the keyring (subkeys stay)...' -ForegroundColor Cyan
        Invoke-Gpg --yes --delete-secret-keys "$fpr!" | Out-Null
        $sec = Invoke-Gpg --list-secret-keys --with-colons $fpr
        if (-not ($sec | Where-Object { $_ -like 'sec:*' } | ForEach-Object { $_.Split(':')[14] -eq '#' })) {
            throw 'Primary secret key still present; check the keyring manually.'
        }
    }
}
finally {
    # Drop our copies of the passphrase and ask the garbage collector to reclaim them. Then kill the gpg-agent
    # for this keyring: the agent caches passphrases (default 10 minutes) and would otherwise hold one after
    # the script has exited. Harmless if no agent is running.
    $passPlain = $null; $a = $null
    [GC]::Collect()
    if ($GnuPGHome) { & gpgconf --homedir $GnuPGHome --kill gpg-agent 2>$null }
}

# -------------------------------------------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------------------------------------------
Write-Host ''
Invoke-Gpg --list-secret-keys --keyid-format long $fpr | Write-Host
Write-Host ''
Write-Host "Fingerprint: $grouped" -ForegroundColor Green
Write-Host "Files in $OutDir :" -ForegroundColor Green
Get-ChildItem -LiteralPath $OutDir -Filter "$fpr.*" | ForEach-Object { '  ' + $_.Name } | Write-Host
Write-Host ''
if ($Storage -eq 'Removable') {
    Write-Host 'Next: clone this stick to a second one kept elsewhere, print the fingerprint, then eject. Keep revoke.asc apart from secret-FULL.asc.' -ForegroundColor Yellow
} else {
    Write-Host 'Next: copy secret-FULL + revoke to two offline USB sticks (separate places), print the fingerprint, then delete them from this machine.' -ForegroundColor Yellow
}
