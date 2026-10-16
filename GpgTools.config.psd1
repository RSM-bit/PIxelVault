@{
    # =========================================================================
    #  GpgTools.config.psd1  --  the SINGLE SOURCE OF TRUTH for keys and paths.
    #
    #  Every engine (Invoke-CustomerExchange, Invoke-NestedProtect,
    #  Invoke-MaskedText) and the menu read this file. Nothing else stores keys.
    #  Any value can still be overridden for one run on an engine's command
    #  line, e.g.  .\Invoke-CustomerExchange.ps1 Send .\x.bin -EncryptToSelf $false
    #
    #  This is a PowerShell data file: a plain hashtable literal. It is read
    #  with Import-PowerShellDataFile, which never executes code, so keep it to
    #  simple values (strings, $true/$false). Single-quote strings; use ''
    #  for a single quote inside. Backslashes need no escaping.
    #
    #  Point the engines at a different copy with -ConfigPath <file> or by
    #  setting the GPGTOOLS_CONFIG environment variable.
    # =========================================================================

    # -- Customer exchange (Send / Receive) --
    CustomerPublicKeyPath = 'C:\Keys\customer_pub.asc'            # the customer's public key file
    CustomerFingerprint   = ''                                    # from the customer, out-of-band (spaces OK)
    MyKeyFingerprint      = ''                                    # printed by NewKeyPair (or New-GpgKeySet)
    MyPrivateKeyPath      = ''                                    # optional: imported if your key isn't in the keyring
    MyPublicKeyExportPath = 'C:\Keys\my_pub.asc'                  # file you send to the customer
    MyUserId              = 'Your Name <you@company.com>'         # used only by NewKeyPair
    KeyAlgorithm          = 'Ed25519'                             # NewKeyPair only: 'Ed25519' (Ed25519/Cv25519) or 'RSA4096'
    EncryptToSelf         = $true                                 # Send also encrypts to your key -> full round-trip check
    OutputNaming          = 'Timestamp'                           # 'Timestamp' (<UTC ISO 8601>.gz.asc) or 'Original' (keep input stem)

    # -- gpg selection and passphrase handling --
    GpgPath               = ''                                    # blank = auto-detect (PATH, Gpg4win, Git for Windows)
    PassphraseMode        = 'Auto'                                # 'Auto' | 'Pinentry' (gpg's window) | 'Prompt' (console, loopback)

    # -- Masking (cover text file) --
    MaskedExtension       = '.txt'                                # extension for the masked cover file

    # -- Protect / Unprotect: two independent encryption layers --
    InnerFingerprint      = ''                                    # inner (real) key; blank falls back to MyKeyFingerprint
    OuterFingerprint      = ''                                    # outer (decoy-layer) key; must differ from inner
    DecoyText             = 'This is a blank placeholder file.'   # what the outer layer decrypts to look like
}
