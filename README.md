# 🔐 CipherVault — Modern Text Encryptor & Decryptor

[![Vanilla JS](https://img.shields.io/badge/JavaScript-ES6+-F7DF1E?logo=javascript&logoColor=black)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![Web Crypto API](https://img.shields.io/badge/Security-Web_Crypto_API-10B981?logo=shield&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-6366F1)](https://github.com/dimefsta/Text-Encryptor)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**CipherVault** is a fast, sleek, client-side web application for text encryption, decryption, and data encoding. Powered by modern web standards and the native **Web Cryptography API**, CipherVault enables military-grade authenticated encryption alongside classical ciphers and developer encodings—all in a beautiful, responsive, dark/light interface.

---

## ✨ Features

- 🛡️ **Multi-Algorithm Engine**:
  - **AES-256-GCM** (Industry-standard authenticated encryption with PBKDF2 key derivation and random salt/IV)
  - **Vigenère Cipher** (Enhanced polyalphabetic substitution supporting extended character sets)
  - **Caesar Cipher** (Classical shift cipher with interactive 1–25 offset slider and numerical stepper)
  - **ROT13** (Symmetric 13-character rotation)
  - **XOR Cipher** (Bitwise stream cipher with hex-encoded output)
  - **Base64** (100% UTF-8 safe, handles emojis, international characters, and symbols)
  - **Hexadecimal** (Base16 byte representation)
  - **URL Percent-Encoding** (Standard URI component format)

- 🎨 **Modern Minimalist UI/UX**:
  - Dark / Light mode with persistent state (`localStorage`) and system preference detection.
  - Fluid glassmorphism styling with ambient background gradients.
  - High-performance monospace typography for plaintext, ciphertexts, and keys.
  - Fully responsive design that adapts smoothly from smartphones to desktop displays.

- ⚡ **Productivity Enhancements**:
  - **One-Click Copy**: Fast clipboard copy with animated visual checkmark confirmation.
  - **File Drag-and-Drop & Upload**: Drop any `.txt`, `.md`, `.json`, or `.log` file directly into the input.
  - **File Download**: Export encrypted or decrypted outputs directly as text files.
  - **Swap Input & Output**: One-click reversal to test decryption immediately.
  - **Key Strength Meter**: Real-time password entropy meter with color-coded strength ratings (*Weak*, *Fair*, *Good*, *Strong*).
  - **Random Key Generator**: One-click generation of 20-character high-entropy secure keys via `crypto.getRandomValues`.
  - **Sample Data Presets**: Instant sample loading for every algorithm to test functionality in one click.
  - **Live Counters & Timers**: Real-time character and word counts, plus execution benchmark timers (in milliseconds).
  - **Toast Notifications**: Non-intrusive, floating status alerts for all user interactions.

- 📖 **In-App Interactive Guide**:
  - Native `<dialog>` modal detailing the fundamental differences between **Encryption** and **Encoding**.
  - Algorithm reference table explaining security levels and recommended use cases.

---

## 📊 Supported Algorithms Comparison

| Algorithm | Category | Security Level | Key Required? | Typical Use Case |
| :--- | :--- | :---: | :---: | :--- |
| **AES-256-GCM** | Authenticated Symmetric | 🟢 **Military-Grade** | Yes (Passphrase) | Passwords, confidential messages, sensitive documents |
| **Vigenère** | Polyalphabetic Substitution | 🟡 **Classical** | Yes (Keyword) | Cryptography education, historical cipher analysis |
| **Caesar Cipher** | Monoalphabetic Shift | 🟡 **Basic Shift** | Shift (1–25) | Simple puzzles, spoiler masking, learning basics |
| **ROT13** | Symmetric 13-Shift | 🟡 **Basic Shift** | None | Forum spoiler tags, casual text obfuscation |
| **XOR Cipher** | Bitwise Stream | 🟡 **Classical** | Yes (Key) | Computer science demonstrations, low-level data masking |
| **Base64** | Binary-to-Text Encoding | 🔵 **None (Encoding)** | None | Binary data embedding, email attachments, Data URIs |
| **Hexadecimal** | Base-16 Encoding | 🔵 **None (Encoding)** | None | Inspecting byte streams, network protocol debugging |
| **URL Encoding** | Percent-Encoding | 🔵 **None (Encoding)** | None | Preparing strings for HTTP query parameters and URIs |

> [!IMPORTANT]
> **Encryption vs. Encoding**: Encodings like Base64, Hex, and URL do **not** provide any confidentiality or data security. Anyone can decode them instantly. Always choose **AES-256-GCM** when protecting confidential information.

---

## 🚀 Quick Start

CipherVault is completely serverless and requires **zero build steps or installations**.

1. Clone the repository:
   ```bash
   git clone https://github.com/dimefsta/Text-Encryptor.git
   cd Text-Encryptor
   ```

2. Open `index.html` directly in any modern browser:
   - On Windows: double-click `index.html` or run `start index.html`
   - On macOS: `open index.html`
   - On Linux: `xdg-open index.html`

Alternatively, serve it locally with any static web server:
```bash
# Python
python -m http.server 8000

# Node.js
npx serve .
```

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
| :--- | :--- |
| <kbd>Ctrl</kbd> / <kbd>Cmd</kbd> + <kbd>Enter</kbd> | **Encrypt** active input text |
| <kbd>Ctrl</kbd> / <kbd>Cmd</kbd> + <kbd>Shift</kbd> + <kbd>Enter</kbd> | **Decrypt** active input text |
| <kbd>Escape</kbd> | Close Help Guide modal |

---

## 🔒 Security & Privacy Guarantee

- **100% Client-Side Processing**: All encryption, decryption, and key generation are executed locally inside your web browser.
- **Zero Network Transmission**: Plaintext messages, secrets, keys, and ciphertexts never leave your machine and are never transmitted to any server or third party.
- **Standards-Compliant Web Crypto**: AES-256 uses the browser's hardware-accelerated `crypto.subtle` with PBKDF2 (100,000 rounds of SHA-256) and a unique, cryptographically random 16-byte salt and 12-byte initialization vector (IV) per encryption.

---

## 📁 Architecture & File Structure

The project strictly adheres to modular separation of concerns:

```
Text-Encryptor/
├── index.html        # Accessible, semantic HTML5 structure & native dialogs
├── style.css         # Modern CSS design system, dark/light themes, animations
├── script.js         # Modular ES6+ engine: algorithms, UI, toasts, entropy
└── README.md         # Comprehensive documentation & security guide
```

---

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).
