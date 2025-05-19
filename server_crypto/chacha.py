class ChaCha:
    """ChaCha20 stream cipher implementation."""

    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    _round_mixup_box = [(0, 4, 8, 12),
                        (1, 5, 9, 13),
                        (2, 6, 10, 14),
                        (3, 7, 11, 15),
                        (0, 5, 10, 15),
                        (1, 6, 11, 12),
                        (2, 7, 8, 13),
                        (3, 4, 9, 14)]
    
    def __init__(self, key: bytes, nonce: bytes, counter: int = 0, rounds: int = 20):
        """
        Initialize the ChaCha cipher with a 256-bit key and 96-bit nonce.
        :param key: 32-byte (256-bit) key.
        :param nonce: 12-byte (96-bit) nonce.
        :param counter: Initial block counter.
        :param rounds: Number of ChaCha rounds (in chacha20 is 20).
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes (256 bits) long")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes (96 bits) long")
        self.key = ChaCha.bytearray_to_words(key)
        self.nonce = ChaCha.bytearray_to_words(nonce)
        self.counter = counter
        self.rounds = rounds

    @staticmethod
    def word_to_bytearray(state: list[int]) -> bytearray:
        """
        Convert the state to a little-endian byte stream manually.
        :param state: List of 32-bit integers (words).
        :return: Bytearray of the state in little-endian order.
        """
        byte_array = bytearray()
        for word in state:
            byte_array.append(word & 0xff)
            byte_array.append((word >> 8) & 0xff)
            byte_array.append((word >> 16) & 0xff)
            byte_array.append((word >> 24) & 0xff)
        return byte_array
    
    @staticmethod
    def bytearray_to_words(data: bytearray) -> list[int]:
        """
        Convert a bytearray into a list of 32-bit integers (words).
        :param data: Bytearray where every 4 bytes represent one 32-bit word.
        :return: List of 32-bit integers extracted from the bytearray.
        """
        ret = []
        for i in range(0, len(data), 4):
            word = (data[i] | (data[i+1] << 8) | (data[i+2] << 16) | (data[i+3] << 24))
            ret.append(word)
        return ret

    @staticmethod
    def rotl32(x: int, y: int) -> int:
        """Rotate left 32-bit integer x by y bits."""
        return ((x << y) | (x >> (32 - y))) & 0xffffffff
    
    @staticmethod
    def quarter_round(x: list[int], a: int, b: int, c: int, d: int) -> None:
        """
        Perform the ChaCha quarter round operation on the state.
        This updates the state list `x` in place according to the ChaCha quarter round
        on the four cells a, b, c, d.

        Operations:
        - A + B
        - D XOR A
        - D <<< 16

        - C + D
        - B XOR C
        - B <<< 12

        - A + B
        - D XOR A
        - D <<< 8

        - C + D
        - B XOR C
        - B <<< 7
        """
        xa = x[a]
        xb = x[b]
        xc = x[c]
        xd = x[d]

        xa = (xa + xb) & 0xffffffff
        xd = xd ^ xa
        xd = ChaCha.rotl32(xd, 16)

        xc = (xc + xd) & 0xffffffff
        xb = xb ^ xc
        xb = ChaCha.rotl32(xb, 12)

        xa = (xa + xb) & 0xffffffff
        xd = xd ^ xa
        xd = ChaCha.rotl32(xd, 8)

        xc = (xc + xd) & 0xffffffff
        xb = xb ^ xc
        xb = ChaCha.rotl32(xb, 7)

        x[a] = xa
        x[b] = xb
        x[c] = xc
        x[d] = xd
    
    @staticmethod
    def double_round(x: list[int]) -> None:
        """Perform two rounds of ChaCha cipher."""
        for a, b, c, d in ChaCha._round_mixup_box:
            ChaCha.quarter_round(x, a, b, c, d)
    
    def chacha_block(self, counter: int) -> list[int]:
        """
        Generate a ChaCha block state using the constants, key, nonce, and the given counter.
        Steps:
        - Initializes the ChaCha state: constants + key + counter + nonce.
        - Copies the state to a working state and applies n `double_round`.
        - Adds the original state and the transformed working state modulo 2^32.
        :param counter: (int) Block counter.
        :return: (list[int]) List of 16 words representing the block state.
        """
        state = ChaCha.constants + self.key + [counter] + self.nonce

        working_state = state[:]
        for _ in range(self.rounds // 2):
            ChaCha.double_round(working_state)

        result = []
        for st, wrkSt in zip(state, working_state):
            result.append((st + wrkSt) & 0xffffffff)

        return result


    def key_stream(self, counter: int) -> bytearray:
        """
        Generates the key stream for nth block.
        :param counter: (int) Block counter offset.
        :return: (bytearray) 64-byte keystream block.
        """
        key_stream = self.chacha_block(self.counter + counter)
        return ChaCha.word_to_bytearray(key_stream)

    def raise_nonce(self):
        """Raises the nonce by 1."""
        for i in range(3):  # 3 parts of the 96-bit nonce
            self.nonce[i] = (self.nonce[i] + 1) & 0xffffffff  # Add 1, wrap at 2^32
            if self.nonce[i] != 0:  # Stop if there's no carry
                break

    def encrypt(self, plaintext: str | bytes | bytearray) -> str:
        """Encrypt plaintext and return the encrypted data as a hex string."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        elif not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("Plaintext must be a string, bytes, or bytearray")

        encrypted_message = bytearray()

        for i in range(0, len(plaintext), 64):
            block = plaintext[i:i + 64]
            key_stream = self.key_stream(i // 64)
            encrypted_block = bytearray(x ^ y for x, y in zip(key_stream, block))
            encrypted_message.extend(encrypted_block)

        self.raise_nonce()
        return encrypted_message.hex()  # Return hex string

    def decrypt(self, hex_ciphertext: str) -> str:
        """Decrypt a hex string ciphertext and return the plaintext string."""
        if not isinstance(hex_ciphertext, str):
            raise TypeError("Ciphertext must be a hex string")

        ciphertext = bytes.fromhex(hex_ciphertext)
        decrypted_text = self.encrypt(ciphertext)
        decrypted_text = bytes.fromhex(decrypted_text).decode('utf-8', errors='ignore')
        return decrypted_text


if __name__ == "__main__":
    # Example usage of ChaCha20
    key = b'\x81\xee\xe1:\xbc\xc6\t\x9e \x03F\xb0v`\xe2n9\xbdb2"\xd1VJ\x0e-\xf2|`C\x02\x93'
    nonce = b'\x81\xee\xe1:\xbc\xc6\t\x9e \x03F\xb0'

    cha_server = ChaCha(key, nonce)
    cha_client = ChaCha(key, nonce)

    plaintext = "Hello, this is a secret message!"

    # Encrypt the plaintext
    encrypted_text = cha_client.encrypt(plaintext)
    print(f"Encrypted text: {encrypted_text}")

    # Decrypt the ciphertext
    decrypted_text = cha_server.decrypt(encrypted_text)
    print(f"Decrypted text: {decrypted_text}")

    # Verify that the decrypted text matches the original plaintext
    assert decrypted_text == plaintext, "Decryption failed!"
    print("Decryption successful!")
