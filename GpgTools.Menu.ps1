#Requires -Version 5.1
# =============================================================================
#  GpgTools.Menu.ps1  --  one text menu for the whole toolset
# -----------------------------------------------------------------------------
#  Does NO crypto itself. Every menu choice gathers inputs (a file from the
#  native Windows file dialog, the occasional yes/no) and then runs one of the
#  standalone scripts in this folder:
#
#    Invoke-NestedProtect.ps1     Protect / Unprotect        (two-key PGP nest)
#    Invoke-CustomerExchange.ps1  Send / Receive / Check / NewKeyPair / ExportPublicKey
#    Invoke-MaskedText.ps1        Mask / Unmask              (whitespace cover .txt)
#    PixelVault.ps1               Pack / Unpack              (AES-GCM PNG container)   [PowerShell 7.4+]
#    New-GpgKeySet.ps1            offline-primary key set    (cert primary + 3 subkeys) [PowerShell 7+]
#
#  Each of those scripts also runs on its own from the command line; the menu is
#  just a convenience front end.
#
#  KEYS LIVE IN ONE PLACE
#    GpgTools.config.psd1 is the single source of truth. This menu NEVER stores
#    a key and NEVER passes a key to an engine; it only READS the config file to
#    show key status and to warn before an operation whose required key is blank.
#    Edit keys there (menu option E opens the file).
#
#  POWERSHELL 7 ITEMS
#    The menu itself runs on Windows PowerShell 5.1. PixelVault and New-GpgKeySet
#    need PowerShell 7. If this session is 5.1 the menu hands those two items off
#    to `pwsh` when it is installed, and says so clearly if it isn't. Those items
#    are marked with a * in the menu.
#
#  LAUNCH
#    Right-click -> Run with PowerShell, or:
#      powershell -ExecutionPolicy Bypass -File .\GpgTools.Menu.ps1
#    Must sit in the SAME folder as the scripts above.
# =============================================================================
[CmdletBinding()]
param(
    # Config file to read for the key-status line and to pass through as
    # -ConfigPath to each engine. Default: GpgTools.config.psd1 next to the menu,
    # or whatever $env:GPGTOOLS_CONFIG points at.
    [string]$ConfigPath,
    # -NoMenu loads the functions without starting the loop (for dot-sourcing in tests).
    [switch]$NoMenu
)
$ErrorActionPreference = 'Stop'

# ===================== paths =====================
# $PSScriptRoot is this menu's own folder; the engines sit beside it.
$script:Root = $PSScriptRoot
# One place that maps a short name to each engine's full path.
$script:Engines = @{
    Nest     = Join-Path $Root 'Invoke-NestedProtect.ps1'
    Customer = Join-Path $Root 'Invoke-CustomerExchange.ps1'
    Mask     = Join-Path $Root 'Invoke-MaskedText.ps1'
    Vault    = Join-Path $Root 'PixelVault.ps1'
    KeySet   = Join-Path $Root 'New-GpgKeySet.ps1'
}
# Which config file the key-status line reads. Same resolution order the
# engines use, so what the menu shows matches what they will load.
$script:ConfigFile = if ($ConfigPath) { $ConfigPath } elseif ($env:GPGTOOLS_CONFIG) { $env:GPGTOOLS_CONFIG } else { Join-Path $Root 'GpgTools.config.psd1' }
# Are we already on PowerShell 7? Decides whether the * items run in-process or via pwsh.
$script:IsPs7 = $PSVersionTable.PSVersion.Major -ge 7

# Fail early and clearly if any engine is missing from the folder.
$missing = $Engines.Values | Where-Object { -not (Test-Path -LiteralPath $_) }
if ($missing) {
    Write-Host "Scripts missing from $Root`:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    if (-not $NoMenu) { exit 1 }
}

# ===================== config (read-only here) =====================
# A cache of just the four fingerprints the menu displays/pre-checks. The menu
# reads the .psd1 directly (with Import-PowerShellDataFile, which never runs
# code) rather than parsing engine source.
$script:Keys = @{ InnerFingerprint = ''; OuterFingerprint = ''; MyKeyFingerprint = ''; CustomerFingerprint = '' }

# Reload the four fingerprints from the config file. Called before every menu
# redraw and before each pre-check, so the display stays current if the user
# edits the config via option E. Any read problem leaves the values blank.
function Update-Keys {
    foreach ($k in @($script:Keys.Keys)) { $script:Keys[$k] = '' }
    if (-not (Test-Path -LiteralPath $script:ConfigFile)) { return }
    try { $cfg = Import-PowerShellDataFile -LiteralPath $script:ConfigFile } catch { return }
    foreach ($k in @($script:Keys.Keys)) { if ($cfg.ContainsKey($k)) { $script:Keys[$k] = "$($cfg[$k])" } }
}

# Pre-flight warning only. The engine re-validates and is the real authority;
# this just saves the user a trip into an engine error when a required key is
# obviously still blank. Returns $true if the key is set.
function Confirm-Key {
    param([string]$Name)
    Update-Keys
    if ([string]::IsNullOrWhiteSpace($script:Keys[$Name])) {
        Write-Host "  '$Name' is blank in $script:ConfigFile." -ForegroundColor Red
        Write-Host "  Set it there (option E), then try again." -ForegroundColor Red
        return $false
    }
    return $true
}

# ===================== file dialogs =====================
# Native "open file" dialog -> chosen path, or $null if cancelled. If
# System.Windows.Forms can't load (a stripped PS host, or non-Windows), fall
# back to typing a path. Trim surrounding quotes a user might paste.
function Select-InputFile {
    param([string]$Title = 'Select a file')
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Title = $Title; $dlg.Filter = 'All files (*.*)|*.*'
        $dlg.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $dlg.FileName }
        return $null
    } catch {
        $p = Read-Host "$Title -- type the full path (blank to cancel)"
        if ([string]::IsNullOrWhiteSpace($p)) { return $null }
        return $p.Trim('"')
    }
}
# Native "save as" dialog -> chosen path, or $null to let the engine auto-name.
# Same console fallback as Select-InputFile.
function Select-OutputFile {
    param([string]$Title = 'Save as', [string]$DefaultName = '')
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $dlg = New-Object System.Windows.Forms.SaveFileDialog
        $dlg.Title = $Title; $dlg.Filter = 'All files (*.*)|*.*'
        $dlg.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
        if ($DefaultName) { $dlg.FileName = $DefaultName }
        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $dlg.FileName }
        return $null
    } catch {
        $p = Read-Host "$Title -- full path (blank = let the tool auto-name)"
        if ([string]::IsNullOrWhiteSpace($p)) { return $null }
        return $p.Trim('"')
    }
}

# ===================== running scripts =====================
# Simple yes/no console prompt with a default; returns $true/$false.
function Read-YesNo {
    param([string]$Prompt, [bool]$Default = $false)
    $hint = if ($Default) { '[Y/n]' } else { '[y/N]' }
    $a = Read-Host "$Prompt $hint"
    if ([string]::IsNullOrWhiteSpace($a)) { return $Default }
    return ($a.Trim() -match '^(y|yes)$')
}

# Print an engine's result object as a list, then a green "done." Secrets are
# never part of a result object, so this is safe to show.
function Show-Result($Result) {
    $text = ($Result | Format-List | Out-String).TrimEnd()
    if ($text) { Write-Host $text }
    Write-Host "  done." -ForegroundColor Green
}

# Run one of the PS 5.1-compatible engines IN THIS SESSION via splatting.
#   $Action  - positional action name for the engine
#   $In      - positional input path (omitted for Check/NewKeyPair/ExportPublicKey)
#   $Named   - a hashtable of named parameters (OutputPath, Mask, MyUserId, ...)
# The menu's own -ConfigPath, if any, is forwarded so the engine reads the same
# config file the menu is showing. The "running:" line echoes the call (no
# secrets are ever on it). Any engine error is caught and shown in red rather
# than crashing the menu loop.
function Invoke-Engine {
    param([string]$Script, [string]$Action, [string]$In = '', [hashtable]$Named = @{})
    try {
        if ($ConfigPath) { $Named.ConfigPath = $ConfigPath }
        $shown = if ($Named.Count) { ' ' + (($Named.GetEnumerator() | ForEach-Object { "-$($_.Key) $($_.Value)" }) -join ' ') } else { '' }
        Write-Host ("  running: $(Split-Path -Leaf $Script) $Action $In$shown".TrimEnd()) -ForegroundColor DarkGray
        if ($In) { $result = & $Script $Action $In @Named } else { $result = & $Script $Action @Named }
        Show-Result $result
    } catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Run a PowerShell 7-ONLY script (PixelVault, New-GpgKeySet).
#   * On PS7: call it in-process and print its result object.
#   * On PS 5.1: locate pwsh and launch the script through it as a child
#     process; if pwsh isn't installed, explain what to do and stop.
# $ArgList is a FLAT argument list: switches as '-Name', values as separate
# items (e.g. @('Pack', $path, '-OutFile', $out, '-NoEncryption')). Passphrase
# prompts happen inside the child script, so nothing secret passes through here.
function Invoke-Ps7Script {
    param([string]$Script, [string[]]$ArgList = @())
    Write-Host ("  running: $(Split-Path -Leaf $Script) $($ArgList -join ' ')".TrimEnd()) -ForegroundColor DarkGray
    try {
        if ($script:IsPs7) {
            $result = & $Script @ArgList
            Show-Result $result
            return
        }
        $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
        if (-not $pwsh) {
            Write-Host '  This item needs PowerShell 7 (pwsh), which is not installed or not on PATH.' -ForegroundColor Red
            Write-Host '  Install from https://aka.ms/powershell or run GpgTools.Menu.ps1 under pwsh.' -ForegroundColor Red
            return
        }
        Write-Host "  (handing off to $($pwsh.Source))" -ForegroundColor DarkGray
        & $pwsh.Source -NoProfile -ExecutionPolicy Bypass -File $Script @ArgList
        if ($LASTEXITCODE -ne 0) { Write-Host "  exit code $LASTEXITCODE" -ForegroundColor Red } else { Write-Host '  done.' -ForegroundColor Green }
    } catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ===================== operations (one per menu choice) =====================
# Each Do-* function: pre-check the required key(s) if any, pick the input file,
# optionally pick an output path or ask a yes/no, then call the engine. NONE of
# them passes a key -- keys come from the config file only.

# 1) Protect: two-key nest. Needs InnerFingerprint + OuterFingerprint in config.
function Do-Protect {
    if (-not (Confirm-Key 'InnerFingerprint')) { return }
    if (-not (Confirm-Key 'OuterFingerprint')) { return }
    $in = Select-InputFile 'Select the file to PROTECT (nest, two keys)'
    if (-not $in) { Write-Host '  cancelled.'; return }
    $named = @{}
    $out = Select-OutputFile 'Protected .asc (Cancel = auto timestamp name in the source folder)'
    if ($out) { $named.OutputPath = $out }
    Invoke-Engine -Script $Engines.Nest -Action 'Protect' -In $in -Named $named
}

# 2) Unprotect: reverse the nest. Same two keys.
function Do-Unprotect {
    if (-not (Confirm-Key 'InnerFingerprint')) { return }
    if (-not (Confirm-Key 'OuterFingerprint')) { return }
    $in = Select-InputFile 'Select the protected .asc to UNPROTECT'
    if (-not $in) { Write-Host '  cancelled.'; return }
    $named = @{}
    $out = Select-OutputFile 'Save recovered file as (Cancel = auto .decrypted name)'
    if ($out) { $named.OutputPath = $out }
    Invoke-Engine -Script $Engines.Nest -Action 'Unprotect' -In $in -Named $named
}

# 3) Send: encrypt to the customer. Needs CustomerFingerprint + MyKeyFingerprint.
#    Offers to also wrap the result in a masked .txt cover.
function Do-Send {
    if (-not (Confirm-Key 'CustomerFingerprint')) { return }
    if (-not (Confirm-Key 'MyKeyFingerprint')) { return }
    $in = Select-InputFile 'Select the file to SEND to the customer'
    if (-not $in) { Write-Host '  cancelled.'; return }
    $named = @{}
    if (Read-YesNo '  Wrap in a masked .txt cover?' $false) { $named.Mask = $true }
    Invoke-Engine -Script $Engines.Customer -Action 'Send' -In $in -Named $named
}

# 4) Receive: decrypt a customer file (auto-unmasks a .txt cover). Needs MyKeyFingerprint.
function Do-Receive {
    if (-not (Confirm-Key 'MyKeyFingerprint')) { return }
    $in = Select-InputFile 'Select the customer file to RECEIVE (.asc or masked .txt)'
    if (-not $in) { Write-Host '  cancelled.'; return }
    $named = @{}
    $out = Select-OutputFile 'Save recovered file as (Cancel = auto .decrypted name)'
    if ($out) { $named.OutputPath = $out }
    Invoke-Engine -Script $Engines.Customer -Action 'Receive' -In $in -Named $named
}

# 5) Mask: wrap any file in a cover .txt. No key needed.
function Do-Mask {
    $in = Select-InputFile 'Select a file to MASK (normally a .asc)'
    if (-not $in) { Write-Host '  cancelled.'; return }
    $named = @{}
    $out = Select-OutputFile 'Masked .txt (Cancel = auto name)'
    if ($out) { $named.OutputPath = $out }
    Invoke-Engine -Script $Engines.Mask -Action 'Mask' -In $in -Named $named
}

# 6) Unmask: recover bytes from a cover .txt. No key needed.
function Do-Unmask {
    $in = Select-InputFile 'Select a masked .txt to UNMASK'
    if (-not $in) { Write-Host '  cancelled.'; return }
    $named = @{}
    $out = Select-OutputFile 'Recovered file (Cancel = auto .asc name)'
    if ($out) { $named.OutputPath = $out }
    Invoke-Engine -Script $Engines.Mask -Action 'Unmask' -In $in -Named $named
}

# 7) Pack: file -> PixelVault PNG (PS7 item). Builds a flat argument list and
#    hands it to Invoke-Ps7Script. The AES passphrase is collected by PixelVault
#    itself, not here.
function Do-Pack {
    $in = Select-InputFile 'Select the file to PACK into a PixelVault PNG (normally a .asc)'
    if (-not $in) { Write-Host '  cancelled.'; return }
    $argList = @('Pack', $in)
    $out = Select-OutputFile 'Output PNG (Cancel = auto IMG_<timestamp>.png next to the input)'
    if ($out) { $argList += @('-OutFile', $out) }
    if (Read-YesNo '  Skip the AES passphrase layer (obfuscation only)?' $false) { $argList += '-NoEncryption' }
    if (Read-YesNo '  Write as base64 text (.png.b64) instead of binary PNG?' $false) { $argList += '-Base64' }
    Write-Host '  PixelVault will ask for its passphrase (twice) unless you skipped encryption.' -ForegroundColor Yellow
    Invoke-Ps7Script -Script $Engines.Vault -ArgList $argList
}

# 8) Unpack: PixelVault PNG -> original file (PS7 item).
function Do-Unpack {
    $in = Select-InputFile 'Select the PixelVault .png (or .png.b64) to UNPACK'
    if (-not $in) { Write-Host '  cancelled.'; return }
    $argList = @('Unpack', $in)
    $out = Select-OutputFile 'Restored file (Cancel = original name stored in the image)'
    if ($out) { $argList += @('-OutFile', $out) }
    Invoke-Ps7Script -Script $Engines.Vault -ArgList $argList
}

# 9) Check: show which gpg the engine will use. No key needed.
function Do-Check { Invoke-Engine -Script $Engines.Customer -Action 'Check' }

# 10) New key pair: simple two-part key for the customer exchange (signing
#     primary + encryption subkey). Reminds the user to put the fingerprint in config.
function Do-NewKeyPair {
    $uid = Read-Host '  Key owner, e.g. "Bear Sunderland <bear@example.com>"'
    if ([string]::IsNullOrWhiteSpace($uid)) { Write-Host '  cancelled.'; return }
    Invoke-Engine -Script $Engines.Customer -Action 'NewKeyPair' -Named @{ MyUserId = $uid }
    Write-Host "  Put the printed fingerprint in MyKeyFingerprint in $script:ConfigFile (and back up the private key)." -ForegroundColor Yellow
}

# 11) New key set: full offline-primary layout via New-GpgKeySet.ps1 (PS7 item).
#     Asks name, email, and whether to write to a USB stick (isolated keyring)
#     or to the local machine (optionally stripping the primary afterwards).
function Do-NewKeySet {
    $name  = Read-Host '  Real name, e.g. Bear Sunderland'
    if ([string]::IsNullOrWhiteSpace($name)) { Write-Host '  cancelled.'; return }
    $email = Read-Host '  Email for the user ID'
    if ([string]::IsNullOrWhiteSpace($email)) { Write-Host '  cancelled.'; return }
    $argList = @('-Name', $name, '-Email', $email)
    if (Read-YesNo '  Write to a removable USB stick with an isolated keyring (recommended)?' $true) {
        $argList += @('-Storage', 'Removable')
    } else {
        $argList += @('-Storage', 'Local')
        if (Read-YesNo '  Strip the primary secret key from the keyring afterwards (-RemovePrimary)?' $true) { $argList += '-RemovePrimary' }
    }
    Write-Host '  New-GpgKeySet asks for one passphrase (twice) and uses it for every step.' -ForegroundColor Yellow
    Invoke-Ps7Script -Script $Engines.KeySet -ArgList $argList
    Write-Host "  Put the printed fingerprint in MyKeyFingerprint (or Inner/OuterFingerprint) in $script:ConfigFile." -ForegroundColor Yellow
}

# 12) Export public key: re-write your public key file. Needs MyKeyFingerprint.
function Do-ExportPublicKey {
    if (-not (Confirm-Key 'MyKeyFingerprint')) { return }
    Invoke-Engine -Script $Engines.Customer -Action 'ExportPublicKey'
}

# E) Edit the config file in the default editor (notepad on Windows; $EDITOR
#    elsewhere). Reload the key cache afterwards so the status line updates.
function Do-EditConfig {
    if (-not (Test-Path -LiteralPath $script:ConfigFile)) { Write-Host "  Config file not found: $script:ConfigFile" -ForegroundColor Red; return }
    try {
        if ($env:OS -eq 'Windows_NT') { Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$script:ConfigFile`"" -Wait }
        elseif ($env:EDITOR) { & $env:EDITOR $script:ConfigFile }
        else { Write-Host "  Edit this file: $script:ConfigFile" }
    } catch { Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red }
    Update-Keys
}

# ===================== menu =====================
# Draw the dim status line: last 8 chars of each configured fingerprint (or
# "(not set)"), the config file path, and -- on PS 5.1 -- whether the * items
# can run via pwsh. Re-reads the config each time so it stays current.
function Show-KeyState {
    Update-Keys
    $tail = {
        param($v)
        $c = ("$v" -replace '\s', '')
        if ([string]::IsNullOrWhiteSpace($c)) { return '(not set)' }
        if ($c.Length -le 8) { return $c }
        return $c.Substring($c.Length - 8)
    }
    Write-Host ("  keys -- inner:{0}  outer:{1}  mine:{2}  customer:{3}" -f `
        (& $tail $script:Keys['InnerFingerprint']), (& $tail $script:Keys['OuterFingerprint']), `
        (& $tail $script:Keys['MyKeyFingerprint']), (& $tail $script:Keys['CustomerFingerprint'])) -ForegroundColor DarkGray
    Write-Host "  config: $script:ConfigFile" -ForegroundColor DarkGray
    if (-not $script:IsPs7) {
        $has7 = [bool](Get-Command pwsh -ErrorAction SilentlyContinue)
        Write-Host ("  PowerShell {0}; items marked * {1}" -f $PSVersionTable.PSVersion, $(if ($has7) { 'run via pwsh' } else { 'need PowerShell 7 (not found)' })) -ForegroundColor DarkGray
    }
}

# Clear the screen and draw the whole menu, including the status line.
function Show-Menu {
    Clear-Host
    Write-Host '==============================================' -ForegroundColor Cyan
    Write-Host '   GPG File Tools' -ForegroundColor Cyan
    Write-Host '==============================================' -ForegroundColor Cyan
    Show-KeyState
    Write-Host ''
    Write-Host '  Two-key nest (personal backup):'
    Write-Host '    1) Protect        (encrypt a file, two keys)'
    Write-Host '    2) Unprotect      (decrypt a protected file)'
    Write-Host ''
    Write-Host '  Customer exchange:'
    Write-Host '    3) Send           (encrypt to customer)'
    Write-Host '    4) Receive        (decrypt customer response)'
    Write-Host ''
    Write-Host '  Cover / obfuscation:'
    Write-Host '    5) Mask           (wrap a .asc as a .txt cover)'
    Write-Host '    6) Unmask         (recover from a .txt cover)'
    Write-Host '    7) Pack *         (file -> PixelVault PNG, AES-GCM passphrase)'
    Write-Host '    8) Unpack *       (PixelVault PNG -> file)'
    Write-Host ''
    Write-Host '  Keys / setup:'
    Write-Host '    9) Check gpg'
    Write-Host '   10) New key pair   (simple: sign primary + encrypt subkey)'
    Write-Host '   11) New key set *  (offline-primary layout, backups to USB)'
    Write-Host '   12) Export public key'
    Write-Host '    E) Edit config file'
    Write-Host ''
    Write-Host '    0) Exit'
    Write-Host ''
}

# The main loop: draw, read a choice (upper-cased so 'e' works), dispatch to the
# matching Do-*, pause, repeat until 0. The while condition -- not a 'break' --
# ends the loop on Exit, so the "Press Enter" pause is correctly skipped there.
function Start-Menu {
    do {
        Show-Menu
        $choice = (Read-Host 'Choose').Trim().ToUpperInvariant()
        Write-Host ''
        switch ($choice) {
            '1'  { Do-Protect }
            '2'  { Do-Unprotect }
            '3'  { Do-Send }
            '4'  { Do-Receive }
            '5'  { Do-Mask }
            '6'  { Do-Unmask }
            '7'  { Do-Pack }
            '8'  { Do-Unpack }
            '9'  { Do-Check }
            '10' { Do-NewKeyPair }
            '11' { Do-NewKeySet }
            '12' { Do-ExportPublicKey }
            'E'  { Do-EditConfig }
            '0'  { }
            default { Write-Host '  not a valid choice.' -ForegroundColor Yellow }
        }
        if ($choice -ne '0') { Write-Host ''; Read-Host 'Press Enter to return to the menu' | Out-Null }
    } while ($choice -ne '0')
    Write-Host 'Bye.'
}

# Start the menu unless -NoMenu was passed (which loads functions only, for tests).
if (-not $NoMenu) { Start-Menu }
