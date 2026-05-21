// popup.js - Główna logika łączenia z serwerem

const API_URL = 'http://127.0.0.1:8000/api';

const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const statusText = document.getElementById('status');

// Funkcja pomocnicza do wyświetlania wiadomości
function showMessage(text, color) {
    statusText.innerText = text;
    statusText.style.color = color;
}

// --- OBSŁUGA REJESTRACJI ---
document.getElementById('registerBtn').addEventListener('click', async () => {
    const email = emailInput.value;
    const password = passwordInput.value;

    if (!email || !password) return showMessage("Podaj email i hasło!", "red");

    showMessage("Generowanie kluczy i rejestracja...", "black");

    try {
        const salt = generateSalt();
        const authKeyHash = await deriveAuthKeyHash(password, salt);

        const response = await fetch(`${API_URL}/register/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email, salt: salt, auth_key_hash: authKeyHash })
        });

        if (response.ok) {
            showMessage("Konto założone! Możesz się zalogować.", "green");
        } else {
            showMessage("Błąd rejestracji. Taki email już istnieje.", "red");
        }
    } catch (error) {
        showMessage("Błąd połączenia: " + error.message, "red");
    }
});

// --- OBSŁUGA LOGOWANIA ---
document.getElementById('loginBtn').addEventListener('click', async () => {
    const email = emailInput.value;
    const password = passwordInput.value;

    if (!email || !password) return showMessage("Podaj email i hasło!", "red");

    showMessage("Logowanie...", "black");

    try {
        // 1. Prośba o sól
        const saltResponse = await fetch(`${API_URL}/get-salt/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email })
        });

        if (!saltResponse.ok) throw new Error("Nie znaleziono użytkownika.");

        const saltData = await saltResponse.json();
        
        // 2. Wyliczenie klucza
        const authKeyHash = await deriveAuthKeyHash(password, saltData.salt);

        // 3. Logowanie po token JWT
        const loginResponse = await fetch(`${API_URL}/login/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email, auth_key_hash: authKeyHash })
        });

        if (loginResponse.ok) {
            const loginData = await loginResponse.json();
            
            // Zapisanie JWT do pamięci
            chrome.storage.local.set({ 'jwtToken': loginData.access }, () => {
                showMessage("Zalogowano pomyślnie! Token zapisany.", "green");
            });
        } else {
            throw new Error("Nieprawidłowe hasło.");
        }
    } catch (error) {
        showMessage("Błąd: " + error.message, "red");
    }
});