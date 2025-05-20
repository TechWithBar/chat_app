# !!! If you run _example.py do this and not line 3:
# from secp256r1 import *
from server_crypto.secp256r1 import *
import hashlib
import secrets

# This code implements the elliptic curve Diffie Hellman (ECDH) key exchange algorithm using the secp256r1 curve.
# It allows two computers to securely share a secret key over the network.

class Point:
    """Represents a point on the elliptic curve."""

    def __init__(self, x, y, curve):
        self._x = x
        self._y = y
        self._curve = curve

        if not self.is_at_infinity() and not curve.is_on_curve(self):
            raise ValueError(f"Point ({x}, {y}) is not on the given curve")

    @property
    def x(self):
        return self._x
    
    @property
    def y(self):
        """Y coordinate of the point."""
        return self._y
    
    @property
    def curve(self):
        return self._curve
    
    def is_at_infinity(self):
        return self.x is None and self.y is None

    def __eq__(self, other):
        """Checks if two points are the same."""
        return (self.x, self.y, self.curve) == (other.x, other.y, other.curve)

    def __add__(self, other):
        """Adds two points on the elliptic curve."""
        if self.curve != other.curve:
            raise ValueError("Cannot add points on different curves")

        if self.is_at_infinity():
            return other
        if other.is_at_infinity():
            return self
        if self.x == other.x and (self.y != other.y or self.y == 0):
            return Point(None, None, self.curve)  # point at infinity

        p = self.curve.p

        # m is the slope
        if self == other:
            # point doubling
            m = (3 * self.x ** 2 + self.curve.a) * pow(2 * self.y, -1, p)
        else:
            # point addition
            m = (other.y - self.y) * pow(other.x - self.x, -1, p)

        m %= p
        x_r = (m * m - self.x - other.x) % p
        y_r = (m * (self.x - x_r) - self.y) % p
        return Point(x_r, y_r, self.curve)

    def scalar_mult(self, k: int):
        """Computes k * P using double-and-add algorithm."""
        if k < 1 or k >= self.curve.n:
            raise ValueError("k must be in the range [1, n-1]")
        result = Point(None, None, self.curve)

        # Start with the current point as the addend
        addend = self

        # Loop through each bit of k (from least significant to most significant)
        while k:
            # If the current least significant bit is 1, add the addend to the result
            if k & 1:
                result += addend

            # Double the point for the next bit
            addend += addend

            # Shift k right by 1 bit
            k >>= 1

        return result
    
    def __repr__(self):
        """String representation of the point."""
        if self.is_at_infinity():
            return f"Point(infinity)"
        return f"Point({self.x}, {self.y})"
    

class ECDH:
    """Elliptic Curve Diffie Hellman key exchange."""

    def __init__(self, a: int, b: int, p: int, n: int, Gx: int, Gy: int):
        self.a = a
        self.b = b
        self.p = p
        self.n = n
        self.G = Point(Gx, Gy, self)

        if not self.is_on_curve(self.G):
            raise ValueError("Base point G is not on the curve")

        if self.G.scalar_mult(self.n - 1).is_at_infinity():
            raise ValueError("(n-1)*G is infinity — invalid n")

    def is_on_curve(self, point: Point):
        """Check if a point is on the curve by placing the point in 
        the equasion and checking if it is true."""
        if point.is_at_infinity():
            return True
        x, y = point.x, point.y
        return (y * y - x ** 3 - self.a * x - self.b) % self.p == 0
    
    def generate_private_key(self):
        """Generate a secure random private key with the secrets library."""
        return secrets.randbelow(self.n - 1) + 1

    def generate_public_key(self, private_key: int):
        """Generate the public key by multiplying the private key with the base point G."""
        if private_key < 1 or private_key >= self.n:
            raise ValueError("Private key must be in the range [1, n-1]")
        
        return self.G.scalar_mult(private_key)

    @staticmethod
    def generate_shared_key(private_key: int, other_public_key: Point) -> bytes:
        """
        Generates the shared secret key by multiplying the private key with the 
        other's public key, and then hashing x, y using sha256 to get a large key.
        :param private_key: (int) The private key. 
        :param other_public_key: (Point) The public key of the other person.
        :return: (bytes) A 32-byte shared secret key
        """
        shared_secret = other_public_key.scalar_mult(private_key)
        
        if shared_secret.is_at_infinity():
            raise ValueError("Shared secret is at infinity")
        
        # Combine the bits of x and y coordinates of the shared secret point
        shared_secret_bytes = (
            shared_secret.x.to_bytes(32, byteorder='big') + 
            shared_secret.y.to_bytes(32, byteorder='big')
        )
        
        # Returns the hashed shared secret bytes
        return hashlib.sha256(shared_secret_bytes).digest()
    
    @staticmethod
    def generate_shared_nonce(shared_key: bytes) -> bytes:
        """
        Generates the nonce for the chacha20 cipher by taking the first 
        12 bytes of the shared key.
        :return: (bytes) A 12-byte nonce.
        """
        return shared_key[:12]
    
    def __repr__(self):
        """String representation of the ECDH object."""
        return f"ECDH(a={self.a}, b={self.b}, p={self.p}, n={self.n}, G=({self.G.x}, {self.G.y}))"


ecdh = ECDH(a, b, p, n, Gx, Gy)

if __name__ == "__main__":
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
    print(f"Shared base nonce (bytes): {ecdh.generate_shared_nonce(shared_secret_client)}")
