# SIFAMELON Private Vault

A lightweight desktop app for encrypting and decrypting private text locally. It uses a graphical interface built with CustomTkinter and can run on a computer without sending your text to a server.

## Features

- Encrypt and decrypt text with AES-256-GCM authenticated encryption.
- Derive encryption keys from a password using Scrypt.
- Generate a fresh random salt and nonce for each encryption.
- Copy the encrypted result to your clipboard.
- No account, network connection, or saved password required.

## Requirements

- Python 3.9 or newer
- Tkinter (included with most Python installations; on some Linux distributions it must be installed separately)
- The Python packages listed in [`requirements.txt`](requirements.txt)

## Run locally

Clone the repository, then open a terminal in the project folder.

### Windows (PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe sifamelon_vault.py
```

### macOS or Linux

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
./.venv/bin/python sifamelon_vault.py
```

If Tkinter is missing on Linux, install your distribution's Tkinter package (often named `python3-tk`) and try again.

## Using the vault

1. Enter the text to protect and create a password of at least 16 characters.
2. Select **Encrypt Text**, then copy and safely store the resulting `SIFAVAULT1:` text.
3. To restore the original text, paste the complete encrypted result into the app, switch to **Unlock Text**, and enter the same password.

The encrypted result is portable text; the app does not currently save or open vault files. The `.sifavault` extension is reserved for vault data files if file support is added later.

## Security notes

- Keep both your encrypted text and password safe. If you lose the password, the original text cannot be recovered.
- A strong, unique password is important. The app requires at least 16 characters.
- The app does not transmit or persist your text or password, but plaintext is necessarily present in the app while you use it. Clear the clipboard after copying sensitive data.
- This project has not been independently security-audited. Do not treat it as a substitute for a reviewed password manager or a secure backup strategy.

## Repository contents

- `sifamelon_vault.py` — application source code
- `requirements.txt` — third-party Python dependencies
- `.gitignore` — excludes local environments, caches, and private vault data

## License

No license has been specified yet. Add a license before allowing others to reuse, modify, or distribute this project.
