// crypto.js - Plik odpowiedzialny za matematykę i szyfrowanie

// Funkcja generująca losową Sól (Salt)
function generateSalt() {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    return btoa(String.fromCharCode.apply(null, salt));
}

// Funkcja wyliczająca Hash (PBKDF2) na podstawie hasła i soli
async function deriveAuthKeyHash(password, saltBase64) {
    const enc = new TextEncoder();
    
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );
    
    const saltBytes = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
    
    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: saltBytes,
            iterations: 100000, 
            hash: "SHA-256"
        },
        keyMaterial,
        256 
    );
    
    return btoa(String.fromCharCode.apply(null, new Uint8Array(derivedBits)));
}