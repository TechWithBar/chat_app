const p = BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
const a = BigInt('0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc');
const b = BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b');
const Gx = BigInt('0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296');
const Gy = BigInt('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5');
const n = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');

/** 
 * Returns a Promise resolving to a Uint8Array of the SHA-256 hash of the input key.
 * @param {Uint8Array} key 
 * @returns {Promise<Uint8Array>}
 */
function sha256(key) {
	return crypto.subtle.digest('SHA-256', key).then(hashBuffer => new Uint8Array(hashBuffer));
}

/**
 * Modulu function so that the answer won't be negative (n % m).
 * @param {number} n 
 * @param {number} m 
 * @returns 
 */
function mod(n, m) {
	return ((n % m) + m) % m;
}

/** 
 * Modular inverse using Extended Euclidean Algorithm.
 * @param {number} a
 * @param {number} m
 */
function modinv(a, m) {
	a = mod(a, m);
	let m0 = m;
	let x0 = 0n, x1 = 1n;

	if (m === 1n) return 0n;

	while (a > 1n) {
		const q = a / m;
		[a, m] = [m, a % m];
		[x0, x1] = [x1 - q * x0, x0];
	}

	if (x1 < 0n) x1 += m0;
	return x1;
}

/**
 * Converts a non-negative BigInt to a Uint8Array of specified length in big-endian order.
 * Big-endian means the most significant byte is at the lowest index (start) of the array.
 * @param {*} n - The bigint.
 * @param {*} byteLength - the length of the output byte array.
 * @returns {Uint8Array} A byte array representing the bigint in big-endian byte order.
 */
function bigintToBytes(n, byteLength = 32) {
	if (n < 0n) throw new Error("Only non-negative BigInts supported");
	const bytes = new Uint8Array(byteLength);
	for (let i = byteLength - 1; i >= 0 && n > 0n; i--) {
		bytes[i] = Number(n & 0xFFn);
		n >>= 8n;
	}
	return bytes;
}

export class Point {
	constructor(x, y, curve) {
		this.x = x;
		this.y = y;
		this.curve = curve;

		if (!this.isAtInfinity() && !curve.isOnCurve(this)) {
			throw new Error(`Point (${x}, ${y}) is not on the given curve`);
		}
	}

	isAtInfinity() {
		return this.x === null && this.y === null;
	}

	/** Checks if two points are the same. */
	equals(other) {
		return (
			this.x === other.x &&
			this.y === other.y &&
			this.curve === other.curve
		);
	}

	/** 
	 * Adds two points on the elliptic curve.
	 * @param {Point} other - The point to add.
	 * @returns {Point} The resulting point.
	 */
	add(other) {
		const { a, p } = this.curve;

		if (this.curve !== other.curve) {
			throw new Error("Cannot add points on different curves");
		}

		if (this.isAtInfinity()) return other;
		if (other.isAtInfinity()) return this;

		if (this.x === other.x && (this.y !== other.y || this.y === 0n)) {
			return new Point(null, null, this.curve); // Point at infinity
		}

		// The slope:
		let m;

		if (this.equals(other)) {
		    // Point doubling (שיפוע משיק)
			m = mod((3n * this.x ** 2n + a) * modinv(2n * this.y, p), p);
		} else {
			// Point addition (שיפוע הישר העובר בשתי הנקודות)
			m = mod((other.y - this.y) * modinv(other.x - this.x, p), p);
		}

		const xR = mod(m * m - this.x - other.x, p);
		const yR = mod(m * (this.x - xR) - this.y, p);

		return new Point(xR, yR, this.curve);
	}


	/** Computes k * P using double-and-add algorithm.
	 * @param {BigInt} k - The scalar multiplier.
	 * @returns {Point} The resulting point.
	 * @throws {Error} If k is not in the range [1, n-1].
	*/
	scalarMult(k) {
		if (k < 1n || k >= this.curve.n) {
			throw new Error("k must be in the range [1, n-1]");
		}

		let result = new Point(null, null, this.curve);

		// Start with the current point as the addend
		let addend = this;

		// Loop through each bit of k (from least significant to most significant)
		while (k > 0n) {
			// If the current least significant bit is 1, add the addend to the result
			if (k & 1n) result = result.add(addend);
			
			// Double the point for the next bit
			addend = addend.add(addend);

			// Shift k right by 1 bit
			k >>= 1n;
		}

		return result;
	}

	toString() {
		if (this.isAtInfinity()) {
			return "Point(infinity)";
		}
		return `Point(${this.x}, ${this.y})`;
	}
}


class ECDH {
	constructor(a, b, p, n, Gx, Gy) {
		this.a = a;
		this.b = b;
		this.p = p;
		this.n = n;
		this.G = new Point(Gx, Gy, this);

		if (!this.isOnCurve(this.G)) {
			throw new Error("Base point G is not on the curve");
		}

		if (this.G.scalarMult(n - 1n).isAtInfinity() === true) {
			throw new Error("(n-1)*G is infinity — invalid n");
		}
	}

	/** Checks if a point is on the curve. */
	isOnCurve(point) {
		if (point.isAtInfinity()) return true;
		const { x, y } = point;
		const left = mod(y ** 2n, this.p);
		const right = mod(x ** 3n + this.a * x + this.b, this.p);
		return left === right;
	}

	/** 
	 * Generates a random private key in the range [1, n-1].
	 * @returns {BigInt} The private key.
	*/
	generatePrivateKey() {
		const byteLength = (this.n.toString(2).length + 7) >> 3;

		while (true) {
			const rand = new Uint8Array(byteLength);
			crypto.getRandomValues(rand);

			let num = 0n;
			for (const byte of rand) {
				num = (num << 8n) + BigInt(byte);
			}

			if (num > 0n && num < this.n) return num;
		}
	}

	/** Generates the public key from the private key.
	 * @param {BigInt} privateKey - The private key.
	 * @returns {Point} The public key.
	 * @throws {Error} If the private key is not in the range [1, n-1].
	*/
	generatePublicKey(privateKey) {
		return this.G.scalarMult(privateKey);
	}

	/** Generates a shared key using the private key and the other party's public key.
	 * @param {BigInt} privateKey - The private key.
	 * @param {Point} otherPublicKey - The other party's public key.
	 * @returns {Promise<Uint8Array>} The shared key (32 bytes).
	 * @throws {Error} If the private key is not in the range [1, n-1].
	 */
	generateSharedKey(privateKey, otherPublicKey) {
		const sharedSecret = otherPublicKey.scalarMult(privateKey);

		if (sharedSecret.isAtInfinity()) {
			throw new Error("Shared secret is at infinity");
		}

		// Convert x and y to 32-byte big-endian arrays
		const xBytes = bigintToBytes(sharedSecret.x, 32);
		const yBytes = bigintToBytes(sharedSecret.y, 32);

		// Concatenate x and y bytes
		const sharedSecretBytes = new Uint8Array([...xBytes, ...yBytes]);

		// Return the sha256 hash (32 bytes Uint8Array)
		return sha256(sharedSecretBytes);
	}

	/** 
	 * Generates a nonce with the first 12 bytes of the key.
	 * @param {Uint8Array} sharedKey - The shared key (32 bytes).
	 * @returns {Uint8Array} The nonce (12 bytes).
	*/
	generateSharedNonce(sharedKey) {
		if (sharedKey.length !== 32) {
			throw new Error("Shared key must be 32 bytes");
		}
		return sharedKey.subarray(0, 12);
	}

	toString() {
		return `ECDH(a=${this.a}, b=${this.b}, p=${this.p}, n=${this.n}, G=(${this.G.x}, ${this.G.y}))`;
	}
}

export const ecdh = new ECDH(a, b, p, n, Gx, Gy);
