import { ecdh, Point } from '/static/js/ecdh.js';
import { ChaCha } from '/static/js/chacha.js';

var socketio = io();

const privateKey = ecdh.generatePrivateKey();
const publicKey = ecdh.generatePublicKey(privateKey);

let chacha = null;

let isYourMessage = false;

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

keyExchange().then((key) => {
    // Initialize ChaCha with the shared key and a nonce (for demo, use a static nonce or derive from key)
    chacha = new ChaCha(key, ecdh.generateSharedNonce(key));

    socketio.on("message", (data) => {
        // Decrypt the incoming message before displaying
        let decrypted = "";
        try {
            decrypted = chacha.decrypt(data.encrypted);
        } catch (e) {
            decrypted = "[decryption error]";
        }
        createMessage(data.name, decrypted);
    });

    document.getElementById("message").addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            sendMessage();
        }
    });
});

const createMessage = (name, msg) => {
    // Check if this is your own message
    const displayName = isYourMessage ? "You" : name;
    const messageClass = isYourMessage ? "message outgoing" : "message incoming";

    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    const messageDiv = document.createElement("div");
    messageDiv.className = messageClass;
    
    messageDiv.innerHTML = `
        <div class="header">
            <div class="name">${displayName}</div>
            <div class="time">${time}</div>
        </div>
        <div class="message-content">${msg}</div>
    `;

    document.getElementById("messages").appendChild(messageDiv);

    // Scroll to the bottom of the messages
    const messagesDiv = document.getElementById("messages");
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
    isYourMessage = false;
};

const sendMessage = () => {
    const messageInput = document.getElementById("message");
    if (messageInput.value == '' || !chacha) return;
    // Encrypt the message before sending
    const encrypted = chacha.encrypt(messageInput.value);
    socketio.emit('message', { data: encrypted });
    messageInput.value = '';
    isYourMessage = true;
};

window.sendMessage = sendMessage;

function leave() {
    socketio.emit('leave', { data: 'leave' });
    window.location.href = "/home";
};
window.leave = leave;