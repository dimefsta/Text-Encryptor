/**
 * ============================================================================
 * CipherVault - Modern Text Encryptor & Decryptor
 * Client-Side Cryptographic & Encoding Suite
 * ============================================================================
 */

'use strict';

// ----------------------------------------------------------------------------
// 1. Toast Notification Manager
// ----------------------------------------------------------------------------
const Toast = {
    container: null,
    maxToasts: 3,

    init() {
        this.container = document.getElementById('toastContainer');
    },

    /**
     * Display a floating toast notification.
     * @param {string} message - Text to display
     * @param {'info'|'success'|'error'|'warning'} type - Visual category
     * @param {number} duration - Display time in ms (default 3500ms)
     */
    show(message, type = 'info', duration = 3500) {
        if (!this.container) this.init();
        if (!this.container) return;

        // Limit stacked toasts: dismiss oldest active toast if at capacity
        const activeToasts = this.container.querySelectorAll('.toast:not(.toast-hiding)');
        if (activeToasts.length >= this.maxToasts) {
            this.dismiss(activeToasts[0]);
        }

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.setAttribute('role', 'alert');

        const iconSvg = this._getIcon(type);
        toast.innerHTML = `
            <span class="toast-icon" aria-hidden="true">${iconSvg}</span>
            <span class="toast-message">${this._escapeHtml(message)}</span>
            <button type="button" class="toast-close" aria-label="Dismiss notification">&times;</button>
        `;

        this.container.appendChild(toast);

        // Auto-dismiss timer
        const timer = setTimeout(() => {
            this.dismiss(toast);
        }, duration);

        // Close button listener
        const closeBtn = toast.querySelector('.toast-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                clearTimeout(timer);
                this.dismiss(toast);
            });
        }

        // Click on toast body to dismiss
        toast.addEventListener('click', () => {
            clearTimeout(timer);
            this.dismiss(toast);
        });
    },

    dismiss(toast) {
        if (!toast || toast._isDismissed) return;
        toast._isDismissed = true;
        toast.classList.add('toast-hiding');

        const removeElement = () => {
            if (toast && toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        };

        // Transitionend listener with guaranteed timer fallback
        toast.addEventListener('transitionend', removeElement, { once: true });
        setTimeout(removeElement, 320);
    },

    _getIcon(type) {
        switch (type) {
            case 'success':
                return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
            case 'error':
                return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`;
            case 'warning':
                return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
            default:
                return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
        }
    },

    _escapeHtml(str) {
        return str.replace(/[&<>"']/g, m => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        }[m]));
    }
};

// ----------------------------------------------------------------------------
// 2. Cryptographic & Encoding Engine
// ----------------------------------------------------------------------------
const CryptoEngine = {
    // Character alphabet for Vigenère / Polyalphabetic cipher
    vigenereAlphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,?!'_-&@#$%*()/:<>|+=~`'\"\\[\\]{}!^",

    // --- AES-256-GCM with PBKDF2 Key Derivation (Web Crypto API) ---
    async aesEncrypt(plaintext, passphrase) {
        if (!passphrase) {
            throw new Error("AES-256 encryption requires a secret passphrase.");
        }

        const encoder = new TextEncoder();
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));

        // Derive key from passphrase using PBKDF2
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            encoder.encode(passphrase),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );

        const key = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt"]
        );

        const encryptedBuffer = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encoder.encode(plaintext)
        );

        // Package: [16 bytes salt] + [12 bytes iv] + [ciphertext with 16 byte auth tag]
        const ciphertextBytes = new Uint8Array(encryptedBuffer);
        const combined = new Uint8Array(salt.length + iv.length + ciphertextBytes.length);
        combined.set(salt, 0);
        combined.set(iv, salt.length);
        combined.set(ciphertextBytes, salt.length + iv.length);

        return this._uint8ArrayToBase64(combined);
    },

    async aesDecrypt(base64Payload, passphrase) {
        if (!passphrase) {
            throw new Error("AES-256 decryption requires a secret passphrase.");
        }

        let combined;
        try {
            combined = this._base64ToUint8Array(base64Payload.trim());
        } catch {
            throw new Error("Invalid Base64 ciphertext format.");
        }

        // Must have at least 16 (salt) + 12 (iv) + 16 (auth tag) = 44 bytes
        if (combined.length < 44) {
            throw new Error("Ciphertext is too short or malformed for AES-GCM.");
        }

        const salt = combined.slice(0, 16);
        const iv = combined.slice(16, 28);
        const data = combined.slice(28);

        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            encoder.encode(passphrase),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );

        const key = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"]
        );

        try {
            const decryptedBuffer = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                key,
                data
            );
            return new TextDecoder().decode(decryptedBuffer);
        } catch {
            throw new Error("Decryption failed. Incorrect passphrase or corrupted ciphertext.");
        }
    },

    // --- Vigenère / Polyalphabetic Substitution ---
    vigenereEncrypt(text, key) {
        if (!key || key.length === 0) {
            throw new Error("Please provide a keyword for the Vigenère cipher.");
        }

        const alpha = this.vigenereAlphabet;
        const len = alpha.length;
        let result = "";
        let keyIdx = 0;

        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            const textIndex = alpha.indexOf(char);

            if (textIndex === -1) {
                // Preserve characters outside the defined alphabet
                result += char;
            } else {
                const kChar = key[keyIdx % key.length];
                const kIndex = alpha.indexOf(kChar);
                const effectiveShift = (kIndex === -1) ? (kChar.charCodeAt(0) % len) : kIndex;

                const newIndex = ((textIndex + effectiveShift) % len + len) % len;
                result += alpha[newIndex];
                keyIdx++;
            }
        }
        return result;
    },

    vigenereDecrypt(text, key) {
        if (!key || key.length === 0) {
            throw new Error("Please provide a keyword for the Vigenère cipher.");
        }

        const alpha = this.vigenereAlphabet;
        const len = alpha.length;
        let result = "";
        let keyIdx = 0;

        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            const textIndex = alpha.indexOf(char);

            if (textIndex === -1) {
                result += char;
            } else {
                const kChar = key[keyIdx % key.length];
                const kIndex = alpha.indexOf(kChar);
                const effectiveShift = (kIndex === -1) ? (kChar.charCodeAt(0) % len) : kIndex;

                const newIndex = ((textIndex - effectiveShift) % len + len) % len;
                result += alpha[newIndex];
                keyIdx++;
            }
        }
        return result;
    },

    // --- Caesar Cipher (Configurable Shift 1–25) ---
    caesarShift(text, shift) {
        shift = ((shift % 26) + 26) % 26;
        let result = "";

        for (let i = 0; i < text.length; i++) {
            const code = text.charCodeAt(i);
            // Uppercase A-Z (65 - 90)
            if (code >= 65 && code <= 90) {
                result += String.fromCharCode(((code - 65 + shift) % 26) + 65);
            }
            // Lowercase a-z (97 - 122)
            else if (code >= 97 && code <= 122) {
                result += String.fromCharCode(((code - 97 + shift) % 26) + 97);
            }
            // Preserve other characters
            else {
                result += text[i];
            }
        }
        return result;
    },

    caesarEncrypt(text, shift) {
        return this.caesarShift(text, shift);
    },

    caesarDecrypt(text, shift) {
        return this.caesarShift(text, -shift);
    },

    // --- ROT13 (Symmetric 13-Shift) ---
    rot13(text) {
        return this.caesarShift(text, 13);
    },

    // --- XOR Cipher with Repeating Key ---
    xorEncrypt(text, key) {
        if (!key || key.length === 0) {
            throw new Error("XOR cipher requires a key.");
        }

        const encoder = new TextEncoder();
        const textBytes = encoder.encode(text);
        const keyBytes = encoder.encode(key);
        const out = new Uint8Array(textBytes.length);

        for (let i = 0; i < textBytes.length; i++) {
            out[i] = textBytes[i] ^ keyBytes[i % keyBytes.length];
        }

        // Return hex string representation for safe display and transmission
        return Array.from(out)
            .map(b => b.toString(16).padStart(2, '0'))
            .join(' ');
    },

    xorDecrypt(hexText, key) {
        if (!key || key.length === 0) {
            throw new Error("XOR cipher requires a key.");
        }

        const cleanHex = hexText.replace(/[^0-9a-fA-F]/g, '');
        if (cleanHex.length === 0) return "";
        if (cleanHex.length % 2 !== 0) {
            throw new Error("Invalid hex length. Hexadecimal strings must have an even number of digits.");
        }

        const cipherBytes = new Uint8Array(cleanHex.length / 2);
        for (let i = 0; i < cleanHex.length; i += 2) {
            cipherBytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
        }

        const keyBytes = new TextEncoder().encode(key);
        const decryptedBytes = new Uint8Array(cipherBytes.length);

        for (let i = 0; i < cipherBytes.length; i++) {
            decryptedBytes[i] = cipherBytes[i] ^ keyBytes[i % keyBytes.length];
        }

        try {
            return new TextDecoder().decode(decryptedBytes);
        } catch {
            throw new Error("Decryption failed. Could not decode UTF-8 plain text.");
        }
    },

    // --- Base64 (UTF-8 / Emoji Safe) ---
    base64Encode(text) {
        const bytes = new TextEncoder().encode(text);
        return this._uint8ArrayToBase64(bytes);
    },

    base64Decode(base64) {
        try {
            const bytes = this._base64ToUint8Array(base64.trim());
            return new TextDecoder().decode(bytes);
        } catch {
            throw new Error("Invalid Base64 sequence.");
        }
    },

    // --- Hexadecimal (Base16) ---
    hexEncode(text) {
        const bytes = new TextEncoder().encode(text);
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join(' ');
    },

    hexDecode(hexString) {
        const clean = hexString.replace(/[^0-9a-fA-F]/g, '');
        if (clean.length === 0) return "";
        if (clean.length % 2 !== 0) {
            throw new Error("Hex string must contain an even number of characters.");
        }
        const bytes = new Uint8Array(clean.length / 2);
        for (let i = 0; i < clean.length; i += 2) {
            bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
        }
        return new TextDecoder().decode(bytes);
    },

    // --- URL Percent-Encoding ---
    urlEncode(text) {
        return encodeURIComponent(text);
    },

    urlDecode(text) {
        try {
            return decodeURIComponent(text);
        } catch {
            throw new Error("Invalid URL-encoded sequence.");
        }
    },

    // --- Helpers ---
    _uint8ArrayToBase64(bytes) {
        let binary = '';
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    },

    _base64ToUint8Array(base64) {
        const clean = base64.replace(/\s+/g, '');
        const binary = atob(clean);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
};

// ----------------------------------------------------------------------------
// 3. Key Strength Analyzer & Generator
// ----------------------------------------------------------------------------
const KeyManager = {
    /**
     * Evaluate key strength and calculate entropy.
     * @param {string} key
     * @returns {{score: number, label: string, className: string}}
     */
    analyze(key) {
        if (!key || key.length === 0) {
            return { score: 0, label: 'None', className: '' };
        }

        let score = 0;
        const len = key.length;

        const hasLower = /[a-z]/.test(key);
        const hasUpper = /[A-Z]/.test(key);
        const hasDigit = /[0-9]/.test(key);
        const hasSpecial = /[^a-zA-Z0-9]/.test(key);

        const variety = [hasLower, hasUpper, hasDigit, hasSpecial].filter(Boolean).length;

        if (len >= 8) score++;
        if (len >= 12 && variety >= 2) score++;
        if (len >= 16 && variety >= 3) score++;
        if (variety === 4 && len >= 14) score = Math.max(score, 4);

        if (score === 0 && len > 0) score = 1;

        const labels = ['None', 'Weak', 'Fair', 'Good', 'Strong'];
        const classes = ['', 'weak', 'fair', 'good', 'strong'];

        return {
            score,
            label: labels[score],
            className: classes[score]
        };
    },

    /**
     * Generate a cryptographically random, high-entropy key.
     * @param {number} length - Target key length
     * @returns {string}
     */
    generateRandomKey(length = 20) {
        const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
        const randomValues = new Uint32Array(length);
        crypto.getRandomValues(randomValues);

        let result = "";
        for (let i = 0; i < length; i++) {
            result += charset[randomValues[i] % charset.length];
        }
        return result;
    }
};

// ----------------------------------------------------------------------------
// 4. Sample Data Presets
// ----------------------------------------------------------------------------
const SamplePresets = {
    aes: {
        message: "Confidential Project Phoenix: The launch coordinates have been verified for Q3. All systems operational.",
        key: "Skyfall-92#OmegaSecurePass"
    },
    vigenere: {
        message: "Meet me at midnight behind the old cathedral. Bring the documents.",
        key: "ENIGMA"
    },
    caesar: {
        message: "The quick brown fox jumps over the lazy dog!",
        shift: 7
    },
    rot13: {
        message: "Why did the developer go broke? Because they used up all their cache!",
    },
    xor: {
        message: "Transmitting top-secret payload over insecure channel.",
        key: "QuantumKey2026"
    },
    base64: {
        message: "Hello World 🌍! Testing UTF-8 encoding with emojis 🚀 & special characters.",
    },
    hex: {
        message: "CipherVault byte representation demo.",
    },
    url: {
        message: "https://example.com/search?query=modern crypto&filter=utf8#results",
    }
};

// ----------------------------------------------------------------------------
// 5. UI Controller & Application State
// ----------------------------------------------------------------------------
const App = {
    // DOM Elements
    elements: {},

    init() {
        this.cacheDOMElements();
        this.initTheme();
        this.bindEvents();
        this.handleAlgoChange();
        this.updateStats();
        Toast.init();
    },

    cacheDOMElements() {
        this.elements = {
            // Header
            themeToggleBtn: document.getElementById('themeToggleBtn'),
            helpBtn: document.getElementById('helpBtn'),
            sampleBtn: document.getElementById('sampleBtn'),

            // Config
            algoSelect: document.getElementById('algoSelect'),
            algoDescription: document.getElementById('algoDescription'),
            algoDescriptionText: document.getElementById('algoDescriptionText'),
            algoSecurityDot: document.getElementById('algoSecurityDot'),

            // Parameters
            keyParamGroup: document.getElementById('keyParamGroup'),
            keyInput: document.getElementById('keyInput'),
            keyLabelText: document.getElementById('keyLabelText'),
            toggleKeyVisibility: document.getElementById('toggleKeyVisibility'),
            generateKeyBtn: document.getElementById('generateKeyBtn'),
            keyStrengthContainer: document.getElementById('keyStrengthContainer'),
            strengthText: document.getElementById('strengthText'),
            strengthSegments: document.querySelector('.strength-bar-segments'),

            caesarParamGroup: document.getElementById('caesarParamGroup'),
            caesarShiftRange: document.getElementById('caesarShiftRange'),
            caesarShiftNumber: document.getElementById('caesarShiftNumber'),
            caesarValBadge: document.getElementById('caesarValBadge'),

            noParamNotice: document.getElementById('noParamNotice'),
            noParamNoticeText: document.getElementById('noParamNoticeText'),

            // Workspace Inputs
            inputText: document.getElementById('inputText'),
            inputStats: document.getElementById('inputStats'),
            pasteInputBtn: document.getElementById('pasteInputBtn'),
            clearInputBtn: document.getElementById('clearInputBtn'),
            fileUploadInput: document.getElementById('fileUploadInput'),
            dropZone: document.getElementById('dropZone'),
            dragOverlay: document.getElementById('dragOverlay'),

            // Actions
            encryptBtn: document.getElementById('encryptBtn'),
            decryptBtn: document.getElementById('decryptBtn'),
            swapBtn: document.getElementById('swapBtn'),

            // Workspace Outputs
            outputText: document.getElementById('outputText'),
            outputStats: document.getElementById('outputStats'),
            execTime: document.getElementById('execTime'),
            copyOutputBtn: document.getElementById('copyOutputBtn'),
            downloadOutputBtn: document.getElementById('downloadOutputBtn'),
            clearOutputBtn: document.getElementById('clearOutputBtn'),
            statusBanner: document.getElementById('statusBanner'),
            statusMessage: document.getElementById('statusMessage'),

            // Help Dialog
            helpModal: document.getElementById('helpModal'),
            closeHelpModal: document.getElementById('closeHelpModal'),
            dialogDoneBtn: document.getElementById('dialogDoneBtn')
        };
    },

    // --- Theme Management ---
    initTheme() {
        const savedTheme = localStorage.getItem('ciphervault-theme');
        if (savedTheme) {
            document.documentElement.setAttribute('data-theme', savedTheme);
        } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
            document.documentElement.setAttribute('data-theme', 'light');
        } else {
            document.documentElement.setAttribute('data-theme', 'dark');
        }
    },

    toggleTheme() {
        const current = document.documentElement.getAttribute('data-theme') || 'dark';
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('ciphervault-theme', next);
        Toast.show(`Switched to ${next} mode`, 'info', 2000);
    },

    // --- Event Bindings ---
    bindEvents() {
        // Theme
        this.elements.themeToggleBtn.addEventListener('click', () => this.toggleTheme());

        // Help Modal
        this.elements.helpBtn.addEventListener('click', () => this.elements.helpModal.showModal());
        this.elements.closeHelpModal.addEventListener('click', () => this.elements.helpModal.close());
        this.elements.dialogDoneBtn.addEventListener('click', () => this.elements.helpModal.close());

        // Light dismiss fallback for dialogs in older browsers
        if (!('closedBy' in HTMLDialogElement.prototype)) {
            this.elements.helpModal.addEventListener('click', (event) => {
                if (event.target !== this.elements.helpModal) return;
                const rect = this.elements.helpModal.getBoundingClientRect();
                const isInside = (
                    rect.top <= event.clientY &&
                    event.clientY <= rect.top + rect.height &&
                    rect.left <= event.clientX &&
                    event.clientX <= rect.left + rect.width
                );
                if (!isInside) this.elements.helpModal.close();
            });
        }

        // Sample loader
        this.elements.sampleBtn.addEventListener('click', () => this.loadSample());

        // Algorithm change
        this.elements.algoSelect.addEventListener('change', () => this.handleAlgoChange());

        // Key operations
        this.elements.keyInput.addEventListener('input', () => this.updateKeyStrength());
        this.elements.toggleKeyVisibility.addEventListener('click', () => this.toggleKeyVisibility());
        this.elements.generateKeyBtn.addEventListener('click', () => this.generateKey());

        // Caesar controls synchronization
        this.elements.caesarShiftRange.addEventListener('input', (e) => {
            this.elements.caesarShiftNumber.value = e.target.value;
            this.elements.caesarValBadge.textContent = `Shift: +${e.target.value}`;
        });
        this.elements.caesarShiftNumber.addEventListener('input', (e) => {
            let val = parseInt(e.target.value, 10);
            if (isNaN(val)) val = 1;
            val = Math.max(1, Math.min(25, val));
            this.elements.caesarShiftRange.value = val;
            this.elements.caesarValBadge.textContent = `Shift: +${val}`;
        });

        // Input stats & drag-drop
        this.elements.inputText.addEventListener('input', () => this.updateStats());
        this.bindDropZone();

        // Toolbar actions
        this.elements.pasteInputBtn.addEventListener('click', () => this.pasteFromClipboard());
        this.elements.clearInputBtn.addEventListener('click', () => {
            this.elements.inputText.value = '';
            this.updateStats();
            this.elements.inputText.focus();
            Toast.show('Input cleared', 'info', 1500);
        });

        this.elements.clearOutputBtn.addEventListener('click', () => {
            this.elements.outputText.value = '';
            this.updateStats();
            this.hideStatus();
            Toast.show('Output cleared', 'info', 1500);
        });

        this.elements.copyOutputBtn.addEventListener('click', () => this.copyOutput());
        this.elements.downloadOutputBtn.addEventListener('click', () => this.downloadOutput());

        // File upload
        this.elements.fileUploadInput.addEventListener('change', (e) => this.handleFileUpload(e));

        // Primary transforms
        this.elements.encryptBtn.addEventListener('click', () => this.executeTransform(true));
        this.elements.decryptBtn.addEventListener('click', () => this.executeTransform(false));
        this.elements.swapBtn.addEventListener('click', () => this.swapInputOutput());

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                if (e.shiftKey) {
                    this.executeTransform(false); // Decrypt
                } else {
                    this.executeTransform(true); // Encrypt
                }
            }
        });
    },

    // --- Dynamic Parameter Visibility & Descriptions ---
    handleAlgoChange() {
        const algo = this.elements.algoSelect.value;
        const keyGroup = this.elements.keyParamGroup;
        const caesarGroup = this.elements.caesarParamGroup;
        const noParamNotice = this.elements.noParamNotice;
        const noticeText = this.elements.noParamNoticeText;
        const descText = this.elements.algoDescriptionText;
        const dot = this.elements.algoSecurityDot;

        // Reset display
        keyGroup.style.display = 'none';
        caesarGroup.style.display = 'none';
        noParamNotice.style.display = 'none';
        dot.className = 'security-dot';

        switch (algo) {
            case 'aes':
                keyGroup.style.display = 'flex';
                this.elements.keyLabelText.textContent = 'Secret Passphrase / Password';
                this.elements.keyInput.placeholder = 'Enter a strong secret passphrase for AES-256';
                descText.textContent = 'Military-grade 256-bit authenticated encryption (AES-GCM via Web Crypto API)';
                dot.classList.add('secure');
                this.updateKeyStrength();
                break;

            case 'vigenere':
                keyGroup.style.display = 'flex';
                this.elements.keyLabelText.textContent = 'Cipher Keyword';
                this.elements.keyInput.placeholder = 'Enter a keyword or phrase (e.g., SECRET)';
                descText.textContent = 'Polyalphabetic substitution cipher using a repeating keyword.';
                dot.classList.add('classical');
                this.updateKeyStrength();
                break;

            case 'caesar':
                caesarGroup.style.display = 'flex';
                descText.textContent = 'Classical monoalphabetic shift cipher (rotates alphabet by N positions).';
                dot.classList.add('classical');
                break;

            case 'rot13':
                noParamNotice.style.display = 'flex';
                noticeText.textContent = 'ROT13 is a fixed 13-shift Caesar cipher and is self-inverting (no key required).';
                descText.textContent = 'Symmetric 13-character rotation cipher for simple obfuscation.';
                dot.classList.add('classical');
                break;

            case 'xor':
                keyGroup.style.display = 'flex';
                this.elements.keyLabelText.textContent = 'Secret XOR Key';
                this.elements.keyInput.placeholder = 'Enter key string for repeating bitwise XOR';
                descText.textContent = 'Bitwise XOR cipher with hex output representation.';
                dot.classList.add('classical');
                this.updateKeyStrength();
                break;

            case 'base64':
                noParamNotice.style.display = 'flex';
                noticeText.textContent = 'Base64 is a binary-to-text encoding format (no secret key used).';
                descText.textContent = 'Binary-to-text data encoding scheme (UTF-8 safe).';
                dot.classList.add('encoding');
                break;

            case 'hex':
                noParamNotice.style.display = 'flex';
                noticeText.textContent = 'Hexadecimal represents raw byte values as base-16 numerals (no key used).';
                descText.textContent = 'Base-16 hexadecimal byte representation.';
                dot.classList.add('encoding');
                break;

            case 'url':
                noParamNotice.style.display = 'flex';
                noticeText.textContent = 'URL percent-encoding for safe transmission across web URIs.';
                descText.textContent = 'URI percent-encoding for web components.';
                dot.classList.add('encoding');
                break;
        }

        if (this.elements.algoDescription) {
            this.elements.algoDescription.title = descText.textContent;
        }

        this.hideStatus();
    },

    // --- Key Strength & Key Generator ---
    updateKeyStrength() {
        const key = this.elements.keyInput.value;
        const analysis = KeyManager.analyze(key);

        this.elements.strengthText.textContent = analysis.label;
        this.elements.strengthText.className = `strength-text ${analysis.className}`;

        const segments = this.elements.strengthSegments;
        segments.className = `strength-bar-segments score-${analysis.score}`;
    },

    toggleKeyVisibility() {
        const input = this.elements.keyInput;
        const showIcon = this.elements.toggleKeyVisibility.querySelector('.eye-show');
        const hideIcon = this.elements.toggleKeyVisibility.querySelector('.eye-hide');

        if (input.type === 'password') {
            input.type = 'text';
            showIcon.style.display = 'none';
            hideIcon.style.display = 'block';
        } else {
            input.type = 'password';
            showIcon.style.display = 'block';
            hideIcon.style.display = 'none';
        }
    },

    generateKey() {
        const key = KeyManager.generateRandomKey(20);
        this.elements.keyInput.value = key;
        // Make visible temporarily so user sees what was generated
        this.elements.keyInput.type = 'text';
        this.elements.toggleKeyVisibility.querySelector('.eye-show').style.display = 'none';
        this.elements.toggleKeyVisibility.querySelector('.eye-hide').style.display = 'block';

        this.updateKeyStrength();
        Toast.show('Strong 20-character key generated!', 'success', 2500);
    },

    // --- Drag & Drop Zone ---
    bindDropZone() {
        const dropZone = this.elements.dropZone;

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.add('drag-active');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.remove('drag-active');
            });
        });

        dropZone.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if (files && files.length > 0) {
                this.readFile(files[0]);
            }
        });
    },

    handleFileUpload(e) {
        const files = e.target.files;
        if (files && files.length > 0) {
            this.readFile(files[0]);
        }
    },

    readFile(file) {
        if (!file) return;
        if (file.size > 2 * 1024 * 1024) {
            Toast.show('File is larger than 2MB limit.', 'error');
            return;
        }

        const reader = new FileReader();
        reader.onload = (event) => {
            this.elements.inputText.value = event.target.result;
            this.updateStats();
            Toast.show(`Loaded "${file.name}" (${file.size} bytes)`, 'success');
        };
        reader.onerror = () => {
            Toast.show('Failed to read file.', 'error');
        };
        reader.readAsText(file);
    },

    // --- Clipboard & Downloads ---
    async pasteFromClipboard() {
        try {
            const text = await navigator.clipboard.readText();
            if (text) {
                this.elements.inputText.value = text;
                this.updateStats();
                Toast.show('Pasted from clipboard', 'info', 1500);
            } else {
                Toast.show('Clipboard is empty', 'warning', 2000);
            }
        } catch {
            Toast.show('Clipboard permission denied. Please paste manually.', 'error');
        }
    },

    async copyOutput() {
        const text = this.elements.outputText.value;
        if (!text) {
            Toast.show('No output text to copy.', 'warning');
            return;
        }

        try {
            await navigator.clipboard.writeText(text);
            this.animateCopySuccess();
            Toast.show('Copied to clipboard!', 'success', 2000);
        } catch {
            // Fallback for older browsers
            this.elements.outputText.select();
            document.execCommand('copy');
            this.animateCopySuccess();
            Toast.show('Copied to clipboard!', 'success', 2000);
        }
    },

    animateCopySuccess() {
        const btn = this.elements.copyOutputBtn;
        const copyIcon = btn.querySelector('.copy-icon');
        const checkIcon = btn.querySelector('.check-icon');
        const span = btn.querySelector('span');

        btn.classList.add('copied');
        copyIcon.style.display = 'none';
        checkIcon.style.display = 'block';
        span.textContent = 'Copied!';

        setTimeout(() => {
            btn.classList.remove('copied');
            copyIcon.style.display = 'block';
            checkIcon.style.display = 'none';
            span.textContent = 'Copy';
        }, 1800);
    },

    downloadOutput() {
        const text = this.elements.outputText.value;
        if (!text) {
            Toast.show('No output to download.', 'warning');
            return;
        }

        const algo = this.elements.algoSelect.value;
        const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `ciphervault-${algo}-${Date.now()}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        Toast.show('Download initiated', 'success');
    },

    swapInputOutput() {
        const inputVal = this.elements.inputText.value;
        const outputVal = this.elements.outputText.value;

        if (!outputVal) {
            Toast.show('Output is empty. Nothing to swap.', 'warning');
            return;
        }

        this.elements.inputText.value = outputVal;
        this.elements.outputText.value = inputVal;
        this.updateStats();
        this.hideStatus();
        Toast.show('Swapped input & output text', 'info', 1800);
    },

    loadSample() {
        const algo = this.elements.algoSelect.value;
        const sample = SamplePresets[algo];

        if (!sample) return;

        this.elements.inputText.value = sample.message;

        if (sample.key !== undefined) {
            this.elements.keyInput.value = sample.key;
            this.updateKeyStrength();
        }

        if (sample.shift !== undefined) {
            this.elements.caesarShiftRange.value = sample.shift;
            this.elements.caesarShiftNumber.value = sample.shift;
            this.elements.caesarValBadge.textContent = `Shift: +${sample.shift}`;
        }

        this.updateStats();
        Toast.show(`Loaded sample for ${algo.toUpperCase()}`, 'info', 2000);
    },

    // --- Statistics & UI Updates ---
    updateStats() {
        const inText = this.elements.inputText.value;
        const inChars = inText.length;
        const inWords = inText.trim() === '' ? 0 : inText.trim().split(/\s+/).length;
        this.elements.inputStats.textContent = `${inChars.toLocaleString()} chars • ${inWords.toLocaleString()} words`;

        const outText = this.elements.outputText.value;
        const outChars = outText.length;
        this.elements.outputStats.textContent = `${outChars.toLocaleString()} chars`;
    },

    showStatus(msg, type = 'info') {
        const banner = this.elements.statusBanner;
        banner.className = `status-banner ${type}`;
        this.elements.statusMessage.textContent = msg;
        banner.style.display = 'flex';
    },

    hideStatus() {
        this.elements.statusBanner.style.display = 'none';
        this.elements.execTime.style.display = 'none';
    },

    // --- Main Transformation Execution ---
    async executeTransform(isEncrypt) {
        const algo = this.elements.algoSelect.value;
        const text = this.elements.inputText.value;
        const key = this.elements.keyInput.value;
        const caesarShift = parseInt(this.elements.caesarShiftRange.value, 10) || 3;

        if (!text) {
            Toast.show(`Please enter text to ${isEncrypt ? 'encrypt' : 'decrypt'}.`, 'warning');
            this.elements.inputText.focus();
            return;
        }

        const startTime = performance.now();
        let result = "";

        try {
            switch (algo) {
                case 'aes':
                    if (isEncrypt) {
                        result = await CryptoEngine.aesEncrypt(text, key);
                    } else {
                        result = await CryptoEngine.aesDecrypt(text, key);
                    }
                    break;

                case 'vigenere':
                    if (isEncrypt) {
                        result = CryptoEngine.vigenereEncrypt(text, key);
                    } else {
                        result = CryptoEngine.vigenereDecrypt(text, key);
                    }
                    break;

                case 'caesar':
                    if (isEncrypt) {
                        result = CryptoEngine.caesarEncrypt(text, caesarShift);
                    } else {
                        result = CryptoEngine.caesarDecrypt(text, caesarShift);
                    }
                    break;

                case 'rot13':
                    result = CryptoEngine.rot13(text);
                    break;

                case 'xor':
                    if (isEncrypt) {
                        result = CryptoEngine.xorEncrypt(text, key);
                    } else {
                        result = CryptoEngine.xorDecrypt(text, key);
                    }
                    break;

                case 'base64':
                    if (isEncrypt) {
                        result = CryptoEngine.base64Encode(text);
                    } else {
                        result = CryptoEngine.base64Decode(text);
                    }
                    break;

                case 'hex':
                    if (isEncrypt) {
                        result = CryptoEngine.hexEncode(text);
                    } else {
                        result = CryptoEngine.hexDecode(text);
                    }
                    break;

                case 'url':
                    if (isEncrypt) {
                        result = CryptoEngine.urlEncode(text);
                    } else {
                        result = CryptoEngine.urlDecode(text);
                    }
                    break;

                default:
                    throw new Error("Selected algorithm is not supported.");
            }

            const endTime = performance.now();
            const elapsed = (endTime - startTime).toFixed(1);

            this.elements.outputText.value = result;
            this.updateStats();

            this.elements.execTime.textContent = `${elapsed} ms`;
            this.elements.execTime.style.display = 'inline-block';

            const actionLabel = isEncrypt ? 'Encrypted' : 'Decrypted';
            this.showStatus(`Successfully ${actionLabel.toLowerCase()} with ${algo.toUpperCase()} in ${elapsed}ms`, 'success');
            Toast.show(`${actionLabel} successfully (${elapsed}ms)`, 'success', 2200);

        } catch (err) {
            this.elements.outputText.value = '';
            this.updateStats();
            this.showStatus(err.message || 'Transformation failed.', 'error');
            Toast.show(err.message || 'Operation failed.', 'error', 4000);
        }
    }
};

// ----------------------------------------------------------------------------
// Application Bootstrap
// ----------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
    App.init();
});
