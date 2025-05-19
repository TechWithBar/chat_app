export class ChaCha {
    /** ChaCha20 stream cipher implementation. */

    static constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    static roundMixupBox = [
        [0, 4, 8, 12],
        [1, 5, 9, 13],
        [2, 6, 10, 14],
        [3, 7, 11, 15],
        [0, 5, 10, 15],
        [1, 6, 11, 12],
        [2, 7, 8, 13],
        [3, 4, 9, 14],
    ];

    constructor(key, nonce, counter = 0, rounds = 20) {
        /** Initialize the ChaCha cipher with a 256-bit key and 96-bit nonce. 
         * @param {Uint8Array} key - 32-byte (256-bit) key.
         * @param {Uint8Array} nonce - 12-byte (96-bit) nonce.
         * @param {number} counter - Initial block counter.
         * @param {number} rounds - The number of rounds.
         */
        if (key.length !== 32) {
            throw new Error("Key must be 32 bytes (256 bits) long");
        }
        if (nonce.length !== 12) {
            throw new Error("Nonce must be 12 bytes (96 bits) long");
        }
        this.key = ChaCha.byteArrayToWords(key);
        this.nonce = ChaCha.byteArrayToWords(nonce);
        this.counter = counter;
        this.rounds = rounds;
    }

    static wordToByteArray(state) {
        /** Convert the state to a little-endian byte stream.
         * @param {Array} state - The state array.
         * @returns {Uint8Array} The byte array.
         */
        const byteArray = new Uint8Array(state.length * 4);
        for (let i = 0; i < state.length; i++) {
            byteArray[i * 4] = state[i] & 0xff;
            byteArray[i * 4 + 1] = (state[i] >>> 8) & 0xff;
            byteArray[i * 4 + 2] = (state[i] >>> 16) & 0xff;
            byteArray[i * 4 + 3] = (state[i] >>> 24) & 0xff;
        }
        return byteArray;
    }

    static byteArrayToWords(data) {
        /** Convert a byte array to an array of 32-bit words.
         * @param {Uint8Array} data - The byte array.
         * @returns {Array} The array of 32-bit words.
         */
        const ret = [];
        for (let i = 0; i < data.length; i += 4) {
            const word = (data[i]) |
                        (data[i + 1] << 8) |
                        (data[i + 2] << 16) |
                        (data[i + 3] << 24);
            ret.push(word >>> 0); // ensure unsigned
        }
        return ret;
    }

    static hexToPlainText(hexString) {
        if (typeof hexString !== 'string' || hexString.length % 2 !== 0) {
            throw new Error("Invalid hex string");
        }

        const bytes = new Uint8Array(hexString.length / 2);
        for (let i = 0; i < hexString.length; i += 2) {
            bytes[i / 2] = parseInt(hexString.substr(i, 2), 16);
        }

        return new TextDecoder().decode(bytes);
    }

    static rotl32(x, y) {
        /** 
         * Rotate left a 32-bit integer x by y bits.
         * @param {number} x - The integer to rotate.
         * @param {number} y - The number of bits to rotate.
         * @returns {number} The rotated integer.
         */
        return ((x << y) | (x >>> (32 - y))) >>> 0;
    }

    static quaterRound(x, a, b, c, d) {
        /**
         * Perform a ChaCha quarter round operation on four elements of the state.
         * @param {number[]} x - The state array.
         * @param {number} a - Index of first element.
         * @param {number} b - Index of second element.
         * @param {number} c - Index of third element.
         * @param {number} d - Index of fourth element.
         */
        let xa = x[a];
        let xb = x[b];
        let xc = x[c];
        let xd = x[d];

        xa = (xa + xb) >>> 0;
        xd ^= xa;
        xd = ChaCha.rotl32(xd, 16);

        xc = (xc + xd) >>> 0;
        xb ^= xc;
        xb = ChaCha.rotl32(xb, 12);

        xa = (xa + xb) >>> 0;
        xd ^= xa;
        xd = ChaCha.rotl32(xd, 8);

        xc = (xc + xd) >>> 0;
        xb ^= xc;
        xb = ChaCha.rotl32(xb, 7);

        x[a] = xa;
        x[b] = xb;
        x[c] = xc;
        x[d] = xd;
    }

    static doubleRound(x) {
        /** 
         * Perform two rounds of ChaCha cipher.
         * @param {number[]} x - The state array.
         */
        for (const [a, b, c, d] of ChaCha.roundMixupBox) {
            ChaCha.quaterRound(x, a, b, c, d);
        }
    }

    chachaBlock(counter) {
        /** 
         * Generates a state of a single block.
         * @param {number} counter - The block counter.
         * @returns {Uint8Array} The generated block.
         */
        const state = [
            ...ChaCha.constants,
            ...this.key,
            counter,
            ...this.nonce
        ];

        const workingState = state.slice();

        for (let i = 0; i < this.rounds / 2; i++) {
            ChaCha.doubleRound(workingState);
        }

        const result = [];
        for (let i = 0; i < state.length; i++) {
            const sum = (state[i] + workingState[i]) >>> 0; // Ensure unsigned 32-bit integer
            result.push(sum);
        }

        return ChaCha.wordToByteArray(result);
    }

    keyStream(counter) {
        /** 
         * Generates a keystream block.
         * @param {number} counter - The block counter.
         * @returns {Uint8Array} The generated keystream block.
         */
        return this.chachaBlock(this.counter + counter);
    }

    raiseNonce() {
        /** Increments the nonce. */
        for (let i = 0; i < 3; i++) {
            this.nonce[i] = (this.nonce[i] + 1) >>> 0; // Add 1 and wrap at 2^32
            if (this.nonce[i] !== 0) {
                break; // Stop if there was no carry
            }
        }
    }

    encrypt(plaintext) {
        /** 
         * Encrypt plaintext (string or Uint8Array) and return hex string of encrypted bytes.
         * @param {string | Uint8Array} plaintext 
         * @returns {string} hex string
         */
        if (typeof plaintext === 'string') {
            plaintext = new TextEncoder().encode(plaintext);
        } else if (!(plaintext instanceof Uint8Array)) {
            throw new TypeError('Plaintext must be a string or Uint8Array');
        }

        const encryptedMessage = new Uint8Array(plaintext.length);

        for (let i = 0; i < plaintext.length; i += 64) {
            const block = plaintext.subarray(i, i + 64);
            const keyStream = this.keyStream(Math.floor(i / 64)); 
            
            for (let j = 0; j < block.length; j++) {
                encryptedMessage[i + j] = block[j] ^ keyStream[j];
            }
        }

        this.raiseNonce();

        // Convert encrypted Uint8Array to hex string
        return Array.from(encryptedMessage).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    decrypt(hexCiphertext) {
        /**
         * Decrypt ciphertext hex string and return UTF-8 plain string.
         * @param {string} hexCiphertext
         * @returns {string}
         */
        if (typeof hexCiphertext !== 'string') {
            throw new TypeError('Ciphertext must be a hex string');
        }

        // Convert hex string to Uint8Array
        const ciphertext = new Uint8Array(hexCiphertext.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

        const decryptedHex = this.encrypt(ciphertext);
        
        return ChaCha.hexToPlainText(decryptedHex);
    }
}