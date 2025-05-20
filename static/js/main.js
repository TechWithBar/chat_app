import { ecdh, Point } from '/static/js/ecdh.js';
import { ChaCha } from '/static/js/chacha.js';

var socketio = io();

// Generates ECDH key pair
const privateKey = ecdh.generatePrivateKey();
const publicKey = ecdh.generatePublicKey(privateKey);

let chacha = null;
let lastDate = "";

/**
 * Performs a key exchange with the server using ECDH,
 * then returns the shared secret key.
 * @returns {Promise<bigint>} - The derived shared key.
 */
function keyExchange() {
    return new Promise((resolve) => {
        const clien_pubkey_dict = {
            client_publicKey: {
                x: publicKey.x.toString(),
                y: publicKey.y.toString()
            }
        };
        socketio.emit('publicKey', clien_pubkey_dict);

        socketio.on('server_publicKey', (data) => {
            const server_pubkey = data.server_publicKey;
            const sharedKey = ecdh.generateSharedKey(
                privateKey,
                new Point(BigInt(server_pubkey.x), BigInt(server_pubkey.y), ecdh)
            );
            resolve(sharedKey);
        });
    });
}

// Run key exchange and then initialize secure communication
keyExchange().then((key) => {
    // Initialize ChaCha with the shared key and a nonce
    chacha = new ChaCha(key, ecdh.generateSharedNonce(key));

    // Handle incoming messages
    socketio.on("message", (data) => {
        // Decrypt the incoming message before displaying
        let decrypted = "";
        try {
            decrypted = chacha.decrypt(data.encrypted);
        } catch (e) {
            decrypted = "[decryption error]";
        }
        createMessage(data.name, decrypted, false);
    });

    // Send message with Enter key
    document.getElementById("message").addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            sendMessage();
        }
    });
});

/**
 * Escape HTML special characters in a string to prevent XSS (Cross Site Scripting).
 * Converts &, <, >, ", and ' into their corresponding HTML text.
 * @param {string} str - The raw input string.
 * @returns {string} - The escaped string safe for HTML.
 */
function escapeHTML(str) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    let escaped = '';
    for (let i = 0; i < str.length; i++) {
        const char = str[i];
        escaped += map[char] || char;
    }
    return escaped;
}

/**
 * Turns a Date object into a string like "20.1.2025".
 * @param {Date} date - A JS Date object.
 * @returns {string} - A formatted date string.
 */
function getDate(date) {
    const day = date.getDate();
    const month = date.getMonth() + 1; // Months are 0-indexed
    const year = date.getFullYear();
    return `${day}.${month}.${year}`;
}

/**
 * Adds a date element to the chat.
 * @param {string} dateString - The date in string.
 */
function addDate(dateString) {
    const dateElement = document.createElement("div");
    dateElement.className = "date";
    dateElement.textContent = dateString;

    document.getElementById("messages").appendChild(dateElement);
}

/**
 * Creates and adds a message bubble to the chat.
 * Displays a date if the date has changed.
 * @param {string} name - The name of the sender.
 * @param {string} msg - The message.
 * @param {bool} isYour - If this is your message.
 */
function createMessage(name, msg, isYour) {
    // Check if this is your own message to determine the class name
    const messageClass = isYour ? "message outgoing" : "message incoming";
    msg = escapeHTML(msg);

    const now = getDate(new Date());
    if (now !== lastDate) {
        lastDate = now;
        addDate(now)
    }

    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    const messageDiv = document.createElement("div");
    messageDiv.className = messageClass;
    
    messageDiv.innerHTML = `
        <div class="header">
            <div class="name">${name}</div>
            <div class="time">${time}</div>
        </div>
        <div class="message-content">${msg}</div>
    `;

    document.getElementById("messages").appendChild(messageDiv);

    // Scroll to the bottom of the messages
    const messagesDiv = document.getElementById("messages");
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
};

/**
 * Sends the encrypted message to the server and
 * also displays it in the chat.
 */
function sendMessage() {
    const messageInput = document.getElementById("message");
    if (messageInput.value == '' || !chacha) return;
    // Encrypt the message before sending
    const encrypted = chacha.encrypt(messageInput.value);
    socketio.emit('message', { data: encrypted });
    createMessage("You", messageInput.value, true);
    messageInput.value = '';
};

/**
 * Tells the server that the client left and redirects to homepage.
*/
function leave() {
    socketio.emit('leave', { data: 'leave' });
    window.location.href = "/home";
};

window.sendMessage = sendMessage;
window.leave = leave;