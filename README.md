# GpgTools

One menu, five standalone scripts, one config file. Every script runs on its own from the command line; the menu only gathers inputs and calls them.

```
GpgTools/
  GpgTools.Menu.ps1             text menu (PS 5.1+); hands PS7-only items to pwsh when running under 5.1
  GpgTools.config.psd1          THE place keys and paths live; everything reads it, nothing else stores keys
  Invoke-CustomerExchange.ps1   Check | NewKeyPair | ExportPublicKey | Send [-Mask] | Receive      (PS 5.1+, gpg 2.2+)
  Invoke-NestedProtect.ps1      Protect | Unprotect  -- two-key PGP nest                             (PS 5.1+, gpg 2.2+)
  Invoke-MaskedText.ps1         Mask | Unmask        -- whitespace cover .txt, no gpg                (PS 5.1+)
  PixelVault.ps1                Pack | Unpack        -- AES-256-GCM PNG container; also dot-sourceable (PS 7.4+)
  New-GpgKeySet.ps1             offline-primary key set with sign/encrypt/auth subkeys              (PS 7+, gpg 2.4+)
  lib/
    GpgTools.Common.ps1         config loader, gpg locator, Invoke-Gpg, passphrase handling, key/file helpers
    GpgTools.MaskedText.ps1     mask/unmask functions (shared by the Mask engine and Send/Receive)
```

## What changed from the previous layout

- `Invoke-DoubleB64Gzip.ps1` was split by job into three engines that share `lib/`. Behaviour, file formats and the result objects are unchanged, so files produced by the old script still open with the new ones (same `.gz.asc` packaging, same `NESTPD` nest trailer, same mask cover).
- Keys moved out of the engine's `param()` block into `GpgTools.config.psd1`. The menu reads the `.psd1` directly instead of regex-scraping the engine source. Precedence: command-line parameter > config file > built-in default. Point at another config with `-ConfigPath <file>` or `$env:GPGTOOLS_CONFIG`.
- `PixelVault.ps1` gained a command-line entry (`Pack` / `Unpack`) so the menu can call it. `. .\PixelVault.ps1` with no arguments still just defines the two functions.
- `New-GpgKeySet.ps1` is unchanged. The menu's "New key pair" (simple two-part key for the customer exchange) and "New key set" (offline-primary layout) are both offered; they are different tools for different purposes.

## Daily use

```powershell
.\GpgTools.Menu.ps1                                          # or right-click -> Run with PowerShell

.\Invoke-CustomerExchange.ps1 Send    .\payload.bin          # -> <UTC timestamp>.gz.asc
.\Invoke-CustomerExchange.ps1 Send    .\payload.bin -Mask    # -> <UTC timestamp>.txt cover
.\Invoke-CustomerExchange.ps1 Receive .\response.asc
.\Invoke-NestedProtect.ps1    Protect .\secret.bin
.\Invoke-NestedProtect.ps1    Unprotect .\20261015T184500Z.asc
.\Invoke-MaskedText.ps1       Mask    .\file.asc
.\PixelVault.ps1              Pack    .\file.asc             # PS7; asks for the AES passphrase twice
.\New-GpgKeySet.ps1 -Name 'Bear Sunderland' -Email 'you@example.com'
```

## Setup

1. Fill in `GpgTools.config.psd1` (menu option `E` opens it). At minimum `MyKeyFingerprint`; `CustomerPublicKeyPath` + `CustomerFingerprint` for Send/Receive; `InnerFingerprint` + `OuterFingerprint` for Protect/Unprotect.
2. `.\Invoke-CustomerExchange.ps1 Check` shows which gpg will be used and how passphrases will be collected.

## Tested

Every engine was run end to end under PowerShell 7.4.6 with GnuPG 2.4.4 against two throwaway keys: Mask/Unmask, Send/Receive (plain and `-Mask`), Protect/Unprotect, PixelVault Pack/Unpack (CLI, `-NoEncryption` and passphrase), and the menu loop. All round trips were byte-identical. Not yet re-tested on Windows PowerShell 5.1 or with Gpg4win's pinentry; the code paths there are unchanged from the previous version.
