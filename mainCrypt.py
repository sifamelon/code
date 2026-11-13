"""
SifCrypt PRIVATE VAULT
A local desktop app for encrypting and decrypting private text.

Install:
    py -m pip install customtkinter cryptography

Run:
    py mainCrypt.py

Security:
- AES-256-GCM authenticated encryption
- Scrypt password-based key derivation
- Random salt and nonce for every encryption
- No network connection and no saved passwords
- If you forget the password, the encrypted text cannot be recovered.
"""

import base64
import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


APP_NAME = "SifCrypt PRIVATE VAULT"
FILE_EXTENSION = ".sifavault"


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from the password using Scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**15,  # A practical desktop setting; increase if your PC is fast.
        r=8,
        p=1,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_text(plaintext: str, password: str) -> str:
    if not plaintext:
        raise ValueError("Enter some text before locking it.")
    if len(password) < 16:
        raise ValueError("Use a password with at least 16 characters.")

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)

    ciphertext = AESGCM(key).encrypt(
        nonce,
        plaintext.encode("utf-8"),
        b"SIFAMELON-VAULT-v1",
    )

    package = {
        "app": "SIFAMELON-VAULT",
        "version": 1,
        "kdf": "scrypt",
        "n": 2**15,
        "r": 8,
        "p": 1,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    raw = json.dumps(package, separators=(",", ":")).encode("utf-8")
    return "SIFAVAULT1:" + base64.urlsafe_b64encode(raw).decode("ascii")


def decrypt_text(encrypted_text: str, password: str) -> str:
    prefix = "SIFAVAULT1:"
    encrypted_text = encrypted_text.strip()

    if not encrypted_text.startswith(prefix):
        raise ValueError("This does not look like a SIFAMELON vault message.")

    try:
        raw = base64.urlsafe_b64decode(encrypted_text[len(prefix):].encode("ascii"))
        package = json.loads(raw.decode("utf-8"))

        if package.get("app") != "SIFAMELON-VAULT" or package.get("version") != 1:
            raise ValueError("Unsupported vault format.")

        # Do not trust arbitrary KDF settings embedded in pasted data.
        if (
            package.get("kdf") != "scrypt"
            or package.get("n") != 2**15
            or package.get("r") != 8
            or package.get("p") != 1
        ):
            raise ValueError("Invalid or unsupported encryption settings.")

        salt = base64.b64decode(package["salt"], validate=True)
        nonce = base64.b64decode(package["nonce"], validate=True)
        ciphertext = base64.b64decode(package["ciphertext"], validate=True)

        if len(salt) != 16 or len(nonce) != 12:
            raise ValueError("Invalid encrypted data.")

        key = derive_key(password, salt)
        plaintext = AESGCM(key).decrypt(
            nonce,
            ciphertext,
            b"SIFAMELON-VAULT-v1",
        )
        return plaintext.decode("utf-8")

    except (KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError,
            ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith(
            ("This does not", "Unsupported", "Invalid")
        ):
            raise
        raise ValueError("Wrong password, damaged text, or invalid vault data.") from None
    except Exception:
        # Includes AES-GCM authentication failure for a wrong password/tampering.
        raise ValueError("Wrong password, damaged text, or invalid vault data.") from None


class VaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(APP_NAME)
        self.geometry("1000x720")
        self.minsize(780, 600)
        self.configure(fg_color="#0b1020")

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.mode = "lock"
        self.password_visible = False

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_header()
        self._build_mode_switch()
        self._build_workspace()
        self._build_footer()
        self.set_mode("lock")

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=30, pady=(24, 12))
        header.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            header,
            text="SifCrypt PRIVATE VAULT",
            font=ctk.CTkFont(family="Arial", size=27, weight="bold"),
            text_color="#e8edff",
        )
        title.grid(row=0, column=0, sticky="w")

        subtitle = ctk.CTkLabel(
            header,
            text="PRIVATE VAULT  •  YOUR TEXT, YOUR KEY",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#8290b5",
        )
        subtitle.grid(row=1, column=0, sticky="w", pady=(2, 0))

        self.security_badge = ctk.CTkLabel(
            header,
            text="●  LOCAL ENCRYPTION",
            text_color="#55d6a2",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#132b2a",
            corner_radius=14,
            padx=13,
            pady=8,
        )
        self.security_badge.grid(row=0, column=1, rowspan=2, sticky="e")

    def _build_mode_switch(self):
        frame = ctk.CTkFrame(
            self, fg_color="#141b30", corner_radius=14, border_width=1,
            border_color="#27314d"
        )
        frame.grid(row=1, column=0, sticky="ew", padx=30, pady=(8, 16))
        frame.grid_columnconfigure((0, 1), weight=1)

        self.lock_tab = ctk.CTkButton(
            frame, text="🔒   LOCK TEXT", height=43, corner_radius=10,
            command=lambda: self.set_mode("lock")
        )
        self.lock_tab.grid(row=0, column=0, padx=6, pady=6, sticky="ew")

        self.unlock_tab = ctk.CTkButton(
            frame, text="🔓   UNLOCK TEXT", height=43, corner_radius=10,
            command=lambda: self.set_mode("unlock")
        )
        self.unlock_tab.grid(row=0, column=1, padx=6, pady=6, sticky="ew")

    def _build_workspace(self):
        self.workspace = ctk.CTkFrame(
            self, fg_color="#11182b", corner_radius=18,
            border_width=1, border_color="#27314d"
        )
        self.workspace.grid(row=2, column=0, sticky="nsew", padx=30, pady=0)
        self.workspace.grid_columnconfigure(0, weight=1)
        self.workspace.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(self.workspace, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=22, pady=(18, 8))
        top.grid_columnconfigure(0, weight=1)

        self.section_title = ctk.CTkLabel(
            top, text="Your private message",
            font=ctk.CTkFont(size=17, weight="bold"),
            text_color="#e8edff"
        )
        self.section_title.grid(row=0, column=0, sticky="w")

        self.text_count = ctk.CTkLabel(
            top, text="0 characters", text_color="#8290b5",
            font=ctk.CTkFont(size=11)
        )
        self.text_count.grid(row=0, column=1, sticky="e")

        self.text_box = ctk.CTkTextbox(
            self.workspace, corner_radius=12, border_width=1,
            border_color="#303c5c", fg_color="#0b1120",
            text_color="#dce5ff", font=ctk.CTkFont(size=14),
            wrap="word"
        )
        self.text_box.grid(row=1, column=0, sticky="nsew", padx=22, pady=(4, 14))
        self.text_box.bind("<KeyRelease>", self._update_count)

        controls = ctk.CTkFrame(self.workspace, fg_color="transparent")
        controls.grid(row=2, column=0, sticky="ew", padx=22, pady=(0, 10))
        controls.grid_columnconfigure(0, weight=1)

        self.password_label = ctk.CTkLabel(
            controls, text="SECRET PASSWORD",
            text_color="#aeb9d6", font=ctk.CTkFont(size=10, weight="bold")
        )
        self.password_label.grid(row=0, column=0, sticky="w", pady=(0, 6))

        password_row = ctk.CTkFrame(controls, fg_color="transparent")
        password_row.grid(row=1, column=0, sticky="ew")
        password_row.grid_columnconfigure(0, weight=1)

        self.password_entry = ctk.CTkEntry(
            password_row, height=42, corner_radius=10,
            placeholder_text="Enter your secret password",
            show="•", fg_color="#0b1120", border_color="#303c5c"
        )
        self.password_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self.show_password_button = ctk.CTkButton(
            password_row, text="Show", width=72, height=42,
            fg_color="#263250", hover_color="#344366",
            command=self.toggle_password
        )
        self.show_password_button.grid(row=0, column=1)

        actions = ctk.CTkFrame(self.workspace, fg_color="transparent")
        actions.grid(row=3, column=0, sticky="ew", padx=22, pady=(5, 20))
        actions.grid_columnconfigure((0, 1, 2), weight=1)

        self.main_button = ctk.CTkButton(
            actions, text="🔒  ENCRYPT TEXT", height=46, corner_radius=11,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#4968e8", hover_color="#3855cc",
            command=self.process_text
        )
        self.main_button.grid(row=0, column=0, sticky="ew", padx=(0, 6))

        self.copy_button = ctk.CTkButton(
            actions, text="COPY RESULT", height=46, corner_radius=11,
            fg_color="#263250", hover_color="#344366",
            command=self.copy_text
        )
        self.copy_button.grid(row=0, column=1, sticky="ew", padx=6)

        self.clear_button = ctk.CTkButton(
            actions, text="CLEAR", height=46, corner_radius=11,
            fg_color="#263250", hover_color="#344366",
            command=self.clear_all
        )
        self.clear_button.grid(row=0, column=2, sticky="ew", padx=(6, 0))

    def _build_footer(self):
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=3, column=0, sticky="ew", padx=30, pady=(12, 18))
        footer.grid_columnconfigure(0, weight=1)

        self.status = ctk.CTkLabel(
            footer, text="Ready • Your password is never saved",
            text_color="#8290b5", font=ctk.CTkFont(size=11)
        )
        self.status.grid(row=0, column=0, sticky="w")

        note = ctk.CTkLabel(
            footer, text="AES-256-GCM  |  SCRYPT  |  OFFLINE",
            text_color="#5e6c91", font=ctk.CTkFont(size=10, weight="bold")
        )
        note.grid(row=0, column=1, sticky="e")

    def set_mode(self, mode):
        self.mode = mode
        if mode == "lock":
            self.lock_tab.configure(fg_color="#4968e8", hover_color="#3855cc")
            self.unlock_tab.configure(fg_color="transparent", hover_color="#263250")
            self.section_title.configure(text="Your private message")
            self.password_label.configure(text="CREATE SECRET PASSWORD  •  MINIMUM 16 CHARACTERS")
            self.password_entry.configure(placeholder_text="Create a strong secret password")
            self.main_button.configure(text="🔒  ENCRYPT TEXT")
            self.status.configure(text="Ready to lock • Your password is never saved")
        else:
            self.unlock_tab.configure(fg_color="#4968e8", hover_color="#3855cc")
            self.lock_tab.configure(fg_color="transparent", hover_color="#263250")
            self.section_title.configure(text="Encrypted text")
            self.password_label.configure(text="ENTER YOUR SECRET PASSWORD")
            self.password_entry.configure(placeholder_text="Enter the password used to lock this text")
            self.main_button.configure(text="🔓  DECRYPT TEXT")
            self.status.configure(text="Ready to unlock • Your password is never saved")

    def toggle_password(self):
        self.password_visible = not self.password_visible
        self.password_entry.configure(show="" if self.password_visible else "•")
        self.show_password_button.configure(
            text="Hide" if self.password_visible else "Show"
        )

    def process_text(self):
        text = self.text_box.get("1.0", "end-1c")
        password = self.password_entry.get()

        try:
            if self.mode == "lock":
                result = encrypt_text(text, password)
                self.text_box.delete("1.0", "end")
                self.text_box.insert("1.0", result)
                self.set_mode("unlock")
                self.status.configure(
                    text="✓ Encrypted successfully • Copy or save your vault text",
                    text_color="#55d6a2"
                )
                messagebox.showinfo(
                    "Text locked",
                    "Your text has been encrypted.\n\n"
                    "Copy the result and keep it somewhere safe. "
                    "You will need the exact password to unlock it."
                )
            else:
                result = decrypt_text(text, password)
                self.text_box.delete("1.0", "end")
                self.text_box.insert("1.0", result)
                self.set_mode("lock")
                self.status.configure(
                    text="✓ Decrypted successfully • Your original text is restored",
                    text_color="#55d6a2"
                )
                messagebox.showinfo("Text unlocked", "Your original text has been restored.")
            self._update_count()
            self.password_entry.delete(0, "end")
        except ValueError as exc:
            messagebox.showerror("Unable to process", str(exc))
            self.status.configure(text="Operation failed • Check your text and password",
                                  text_color="#ff8b8b")

    def copy_text(self):
        content = self.text_box.get("1.0", "end-1c")
        if not content:
            messagebox.showwarning("Nothing to copy", "There is no text to copy.")
            return
        self.clipboard_clear()
        self.clipboard_append(content)
        self.update()
        self.status.configure(text="✓ Copied to clipboard • Clear clipboard when finished",
                              text_color="#55d6a2")

    def clear_all(self):
        self.text_box.delete("1.0", "end")
        self.password_entry.delete(0, "end")
        self._update_count()
        self.status.configure(text="Cleared • Ready for a new operation",
                              text_color="#8290b5")

    def _update_count(self, _event=None):
        count = len(self.text_box.get("1.0", "end-1c"))
        self.text_count.configure(text=f"{count:,} characters")


if __name__ == "__main__":
    app = VaultApp()
    app.mainloop()
