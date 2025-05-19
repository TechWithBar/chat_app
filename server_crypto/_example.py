from chacha import ChaCha
from ecdh import ECDH
from secp256r1 import *

# !!!
# Before running: change the import in ecdh.py to - from secp256r1 import *

if __name__ == "__main__":
    ecdh = ECDH(a, b, p, n, Gx, Gy)

    # Client and Server generate their private keys
    client_private_key = ecdh.generate_private_key()
    server_private_key = ecdh.generate_private_key()

    # Client and Server generate their public keys
    client_public_key = ecdh.generate_public_key(client_private_key)
    server_public_key = ecdh.generate_public_key(server_private_key)

    # Client computes the shared secret using Server's public key and its private key
    shared_secret_client = ecdh.generate_shared_key(client_private_key, server_public_key)

    # Server computes the shared secret using Client's public key and its private key
    shared_secret_server = ecdh.generate_shared_key(server_private_key, client_public_key)

    # Verify that both shared secrets are the same
    assert shared_secret_client == shared_secret_server, "Shared keys do not match!"

    # Print the 256-bit key (in int format)
    print(f"Shared key (bytes): {shared_secret_client}")
    print(f"Shared base nonce (bytes): {ecdh.generate_shared_nonce(shared_secret_client)}\n")

    # Example usage of ChaCha20
    key = shared_secret_client
    nonce = ecdh.generate_shared_nonce(shared_secret_client)

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
    