/**
 * Red Team Platform - Client-side Encryption Utilities
 * Provides AES-256 encryption/decryption and secure communication helpers
 */

class RedTeamCrypto {
    constructor() {
        this.algorithm = 'AES-GCM';
        this.keyLength = 256;
        this.ivLength = 12; // 96 bits for GCM
        this.tagLength = 16; // 128 bits for GCM
    }

    /**
     * Generate a cryptographically secure random key
     */
    async generateKey() {
        return await crypto.subtle.generateKey(
            {
                name: this.algorithm,
                length: this.keyLength
            },
            true, // extractable
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Generate a random initialization vector
     */
    generateIV() {
        return crypto.getRandomValues(new Uint8Array(this.ivLength));
    }

    /**
     * Convert string to ArrayBuffer
     */
    stringToArrayBuffer(str) {
        return new TextEncoder().encode(str);
    }

    /**
     * Convert ArrayBuffer to string
     */
    arrayBufferToString(buffer) {
        return new TextDecoder().decode(buffer);
    }

    /**
     * Convert ArrayBuffer to base64
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /**
     * Convert base64 to ArrayBuffer
     */
    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    /**
     * Derive key from password using PBKDF2
     */
    async deriveKeyFromPassword(password, salt, iterations = 100000) {
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            this.stringToArrayBuffer(password),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: iterations,
                hash: 'SHA-256'
            },
            keyMaterial,
            {
                name: this.algorithm,
                length: this.keyLength
            },
            true,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt data with AES-256-GCM
     */
    async encryptData(data, key) {
        const iv = this.generateIV();
        const encodedData = this.stringToArrayBuffer(data);

        const encryptedData = await crypto.subtle.encrypt(
            {
                name: this.algorithm,
                iv: iv
            },
            key,
            encodedData
        );

        // Combine IV and encrypted data
        const combined = new Uint8Array(iv.length + encryptedData.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encryptedData), iv.length);

        return this.arrayBufferToBase64(combined.buffer);
    }

    /**
     * Decrypt data with AES-256-GCM
     */
    async decryptData(encryptedData, key) {
        const combined = new Uint8Array(this.base64ToArrayBuffer(encryptedData));
        
        // Extract IV and encrypted data
        const iv = combined.slice(0, this.ivLength);
        const data = combined.slice(this.ivLength);

        const decryptedData = await crypto.subtle.decrypt(
            {
                name: this.algorithm,
                iv: iv
            },
            key,
            data
        );

        return this.arrayBufferToString(decryptedData);
    }

    /**
     * Generate secure random token
     */
    generateSecureToken(length = 32) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return this.arrayBufferToBase64(array.buffer);
    }

    /**
     * Hash data using SHA-256
     */
    async hashData(data) {
        const encodedData = this.stringToArrayBuffer(data);
        const hashBuffer = await crypto.subtle.digest('SHA-256', encodedData);
        return this.arrayBufferToBase64(hashBuffer);
    }

    /**
     * Secure password validation
     */
    validatePasswordStrength(password) {
        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        const score = [
            password.length >= minLength,
            hasUpperCase,
            hasLowerCase,
            hasNumbers,
            hasSpecialChar
        ].reduce((score, criteria) => score + (criteria ? 1 : 0), 0);

        const strength = {
            0: 'Very Weak',
            1: 'Weak',
            2: 'Fair',
            3: 'Good',
            4: 'Strong',
            5: 'Very Strong'
        };

        return {
            score: score,
            strength: strength[score],
            valid: score >= 3,
            requirements: {
                minLength: password.length >= minLength,
                hasUpperCase,
                hasLowerCase,
                hasNumbers,
                hasSpecialChar
            }
        };
    }
}

/**
 * Secure communication helpers
 */
class SecureComm {
    constructor() {
        this.crypto = new RedTeamCrypto();
        this.sessionKey = null;
    }

    /**
     * Initialize secure session
     */
    async initializeSession() {
        this.sessionKey = await this.crypto.generateKey();
        
        // Store session key securely (in production, this would use more secure storage)
        const exportedKey = await crypto.subtle.exportKey('raw', this.sessionKey);
        sessionStorage.setItem('rt_session_key', this.crypto.arrayBufferToBase64(exportedKey));
        
        console.log('Secure session initialized');
    }

    /**
     * Get or create session key
     */
    async getSessionKey() {
        if (this.sessionKey) {
            return this.sessionKey;
        }

        const storedKey = sessionStorage.getItem('rt_session_key');
        if (storedKey) {
            const keyBuffer = this.crypto.base64ToArrayBuffer(storedKey);
            this.sessionKey = await crypto.subtle.importKey(
                'raw',
                keyBuffer,
                { name: 'AES-GCM' },
                true,
                ['encrypt', 'decrypt']
            );
            return this.sessionKey;
        }

        await this.initializeSession();
        return this.sessionKey;
    }

    /**
     * Encrypt request data
     */
    async encryptRequest(data) {
        const key = await this.getSessionKey();
        const encrypted = await this.crypto.encryptData(JSON.stringify(data), key);
        
        return {
            encrypted: encrypted,
            timestamp: Date.now(),
            nonce: this.crypto.generateSecureToken(16)
        };
    }

    /**
     * Decrypt response data
     */
    async decryptResponse(encryptedResponse) {
        const key = await this.getSessionKey();
        const decrypted = await this.crypto.decryptData(encryptedResponse.encrypted, key);
        return JSON.parse(decrypted);
    }

    /**
     * Secure fetch wrapper
     */
    async secureFetch(url, options = {}) {
        const defaultOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        };

        const mergedOptions = { ...defaultOptions, ...options };

        // Encrypt request body if present
        if (mergedOptions.body && mergedOptions.method !== 'GET') {
            const encryptedBody = await this.encryptRequest(JSON.parse(mergedOptions.body));
            mergedOptions.body = JSON.stringify(encryptedBody);
            mergedOptions.headers['X-Encrypted'] = 'true';
        }

        // Add CSRF token if available
        const csrfToken = document.querySelector('meta[name="csrf-token"]');
        if (csrfToken) {
            mergedOptions.headers['X-CSRFToken'] = csrfToken.getAttribute('content');
        }

        try {
            const response = await fetch(url, mergedOptions);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                const responseData = await response.json();
                
                // Decrypt response if encrypted
                if (response.headers.get('X-Encrypted') === 'true') {
                    return await this.decryptResponse(responseData);
                }
                
                return responseData;
            }

            return await response.text();
        } catch (error) {
            console.error('Secure fetch error:', error);
            throw error;
        }
    }

    /**
     * Clear session
     */
    clearSession() {
        this.sessionKey = null;
        sessionStorage.removeItem('rt_session_key');
        console.log('Secure session cleared');
    }
}

/**
 * Form encryption utilities
 */
class FormEncryption {
    constructor() {
        this.crypto = new RedTeamCrypto();
        this.secureComm = new SecureComm();
    }

    /**
     * Encrypt sensitive form fields
     */
    async encryptSensitiveFields(form) {
        const sensitiveFields = ['password', 'token', 'secret', 'key'];
        const formData = new FormData(form);
        const encryptedData = {};
        
        const sessionKey = await this.secureComm.getSessionKey();

        for (let [name, value] of formData.entries()) {
            if (sensitiveFields.some(field => name.toLowerCase().includes(field))) {
                encryptedData[name] = await this.crypto.encryptData(value, sessionKey);
            } else {
                encryptedData[name] = value;
            }
        }

        return encryptedData;
    }

    /**
     * Setup automatic form encryption
     */
    setupAutoEncryption() {
        document.addEventListener('submit', async (event) => {
            const form = event.target;
            
            if (form.hasAttribute('data-encrypt')) {
                event.preventDefault();
                
                try {
                    const encryptedData = await this.encryptSensitiveFields(form);
                    
                    // Create hidden input with encrypted data
                    const hiddenInput = document.createElement('input');
                    hiddenInput.type = 'hidden';
                    hiddenInput.name = 'encrypted_data';
                    hiddenInput.value = JSON.stringify(encryptedData);
                    
                    form.appendChild(hiddenInput);
                    
                    // Remove original form data
                    const sensitiveFields = ['password', 'token', 'secret', 'key'];
                    const inputs = form.querySelectorAll('input');
                    inputs.forEach(input => {
                        if (sensitiveFields.some(field => input.name.toLowerCase().includes(field))) {
                            input.value = '';
                        }
                    });
                    
                    form.submit();
                } catch (error) {
                    console.error('Form encryption error:', error);
                    alert('Error encrypting form data. Please try again.');
                }
            }
        });
    }
}

/**
 * Anti-forensics utilities
 */
class AntiForensics {
    constructor() {
        this.clearTimer = null;
        this.clearInterval = 300000; // 5 minutes
    }

    /**
     * Clear sensitive data from memory
     */
    clearSensitiveData() {
        // Clear form inputs
        const sensitiveInputs = document.querySelectorAll('input[type="password"], input[name*="token"], input[name*="key"]');
        sensitiveInputs.forEach(input => {
            input.value = '';
        });

        // Clear session storage
        const sensitiveKeys = Object.keys(sessionStorage).filter(key => 
            key.includes('token') || key.includes('key') || key.includes('secret')
        );
        sensitiveKeys.forEach(key => sessionStorage.removeItem(key));

        // Clear local storage
        const localSensitiveKeys = Object.keys(localStorage).filter(key => 
            key.includes('token') || key.includes('key') || key.includes('secret')
        );
        localSensitiveKeys.forEach(key => localStorage.removeItem(key));

        console.log('Sensitive data cleared');
    }

    /**
     * Setup automatic data clearing
     */
    setupAutoClear() {
        // Clear on page unload
        window.addEventListener('beforeunload', () => {
            this.clearSensitiveData();
        });

        // Clear on tab visibility change
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.clearSensitiveData();
            }
        });

        // Periodic clearing
        this.clearTimer = setInterval(() => {
            this.clearSensitiveData();
        }, this.clearInterval);

        console.log('Auto-clear initialized');
    }

    /**
     * Disable debugging tools
     */
    disableDebugging() {
        // Disable right-click context menu
        document.addEventListener('contextmenu', (e) => {
            e.preventDefault();
        });

        // Disable F12 and other debug keys
        document.addEventListener('keydown', (e) => {
            if (e.key === 'F12' || 
                (e.ctrlKey && e.shiftKey && e.key === 'I') ||
                (e.ctrlKey && e.shiftKey && e.key === 'J') ||
                (e.ctrlKey && e.key === 'U')) {
                e.preventDefault();
                console.clear();
            }
        });

        // Detect dev tools
        let devtools = { open: false, orientation: null };
        const threshold = 160;

        setInterval(() => {
            if (window.outerHeight - window.innerHeight > threshold || 
                window.outerWidth - window.innerWidth > threshold) {
                if (!devtools.open) {
                    devtools.open = true;
                    console.clear();
                    this.clearSensitiveData();
                }
            } else {
                devtools.open = false;
            }
        }, 500);
    }

    /**
     * Clear debugging artifacts
     */
    clearConsole() {
        if (typeof console !== 'undefined') {
            console.clear();
        }
    }
}

// Initialize global instances
const redTeamCrypto = new RedTeamCrypto();
const secureComm = new SecureComm();
const formEncryption = new FormEncryption();
const antiForensics = new AntiForensics();

// Auto-initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Initialize secure session
    secureComm.initializeSession();
    
    // Setup form encryption
    formEncryption.setupAutoEncryption();
    
    // Setup anti-forensics
    antiForensics.setupAutoClear();
    
    // Disable debugging in production
    if (window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
        antiForensics.disableDebugging();
    }
    
    console.log('Red Team Platform encryption initialized');
});

// Export for use in other scripts
window.RedTeamCrypto = {
    crypto: redTeamCrypto,
    secureComm: secureComm,
    formEncryption: formEncryption,
    antiForensics: antiForensics
};
