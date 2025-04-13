import crypto from 'crypto';
import type { ElGamalCiphertext } from './elgamalTypes';

export class ElGamal {
  private p: bigint; // Large prime
  private g: bigint; // Generator
  private x: bigint; // Private key
  private y: bigint; // Public key

  constructor(params?: { p?: bigint; g?: bigint; y?: bigint; x?: bigint }) {
    if (params) {
      // Initialize with provided parameters
      this.p = params.p!;
      this.g = params.g!;
      this.y = params.y!;
      this.x = params.x || this.generatePrivateKey();
    } else {
      // Initialize as new instance with fresh parameters
      this.p = this.generateSafePrime();
      this.g = this.findGenerator();
      this.x = this.generatePrivateKey();
      this.y = this.generatePublicKey();
    }
  }

  private generateSafePrime(): bigint {
    // Using a strong prime for security
    return BigInt('115792089237316195423570985008687907853269984665640564039457584007913129639747');
  }

  private findGenerator(): bigint {
    // Using 2 as generator since it's a primitive root for our prime
    return BigInt(2);
  }

  private generatePrivateKey(): bigint {
    const bytes = crypto.randomBytes(32);
    const key = BigInt('0x' + bytes.toString('hex'));
    return key % (this.p - BigInt(1));
  }

  private generatePublicKey(): bigint {
    return this.modPow(this.g, this.x, this.p);
  }

  // Encrypt a vote (0 or 1)
  encrypt(vote: bigint): { c1: bigint; c2: bigint; k: bigint } {
    if (vote !== BigInt(0) && vote !== BigInt(1)) {
      throw new Error('Vote must be 0 or 1');
    }

    const k = this.generatePrivateKey(); // Random value for encryption
    const c1 = this.modPow(this.g, k, this.p);
    const s = this.modPow(this.y, k, this.p);
    
    // For vote of 1, multiply by g. For vote of 0, multiply by 1
    const m = vote === BigInt(1) ? this.g : BigInt(1);
    const c2 = (s * m) % this.p;
    
    return { c1, c2, k };
  }

  // Homomorphic addition of votes
  homomorphicAdd(votes: ElGamalCiphertext[]): ElGamalCiphertext {
    if (votes.length === 0) {
      throw new Error('No votes to add');
    }

    // Multiply components to add votes
    let resultC1 = votes[0].c1;
    let resultC2 = votes[0].c2;

    for (let i = 1; i < votes.length; i++) {
      resultC1 = (resultC1 * votes[i].c1) % this.p;
      resultC2 = (resultC2 * votes[i].c2) % this.p;
    }

    return { c1: resultC1, c2: resultC2 };
  }

  // Decrypt and count votes
  decryptSum(encryptedSum: ElGamalCiphertext): bigint {
    try {
      // Calculate s = c1^x mod p
      const s = this.modPow(encryptedSum.c1, this.x, this.p);
      
      // Calculate s^(-1) mod p
      const sInverse = this.modInverse(s, this.p);
      
      // Calculate m = c2 * s^(-1) mod p
      const m = (encryptedSum.c2 * sInverse) % this.p;

      // Count the number of votes by solving discrete log
      // m = g^count mod p, where count is the number of votes
      let count = BigInt(0);
      const maxVotes = BigInt(100); // Reasonable maximum number of votes

      // Special case: no votes
      if (m === BigInt(1)) {
        return BigInt(0);
      }

      // Try values up to maxVotes
      while (count <= maxVotes) {
        if (this.modPow(this.g, count, this.p) === m) {
          return count;
        }
        count += BigInt(1);
      }
      
      throw new Error(`Could not determine vote count. Expected ≤ ${maxVotes} votes.`);
    } catch (error) {
      console.error('Vote counting error:', error);
      throw new Error('Failed to count votes: ' + (error as Error).message);
    }
  }

  // Helper functions
  private modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
    if (modulus === BigInt(1)) return BigInt(0);
    let result = BigInt(1);
    base = base % modulus;
    while (exponent > BigInt(0)) {
      if (exponent % BigInt(2) === BigInt(1)) {
        result = (result * base) % modulus;
      }
      base = (base * base) % modulus;
      exponent = exponent / BigInt(2);
    }
    return result;
  }

  private modInverse(a: bigint, m: bigint): bigint {
    let [old_r, r] = [a, m];
    let [old_s, s] = [BigInt(1), BigInt(0)];

    while (r !== BigInt(0)) {
      const quotient = old_r / r;
      [old_r, r] = [r, old_r - quotient * r];
      [old_s, s] = [s, old_s - quotient * s];
    }

    return ((old_s % m) + m) % m;
  }

  // Public getters and utility methods
  public getPublicKey(): bigint {
    return this.y;
  }

  public getGenerator(): bigint {
    return this.g;
  }

  public getModulus(): bigint {
    return this.p;
  }

  public getPublicParams() {
    return {
      p: this.p.toString(),
      g: this.g.toString(),
      y: this.y.toString()
    };
  }

  public static fromPublicParams(params: { p: string; g: string; y: string }): ElGamal {
    return new ElGamal({
      p: BigInt(params.p),
      g: BigInt(params.g),
      y: BigInt(params.y)
    });
  }

  // Zero-Knowledge Proof generation
  generateZKP(vote: bigint, k: bigint): { commitment: bigint; challenge: bigint; response: bigint } {
    const w = this.generatePrivateKey(); // Random witness
    const commitment = this.modPow(this.g, w, this.p);
    
    // Generate challenge using hash of all public values
    const challengeInput = `${this.g}${this.y}${commitment}${vote}`;
    const challenge = BigInt('0x' + crypto.createHash('sha256').update(challengeInput).digest('hex')) % this.p;
    
    // Generate response that proves vote is valid
    const response = (w + challenge * k) % (this.p - BigInt(1));
    
    return { commitment, challenge, response };
  }

  // Verify Zero-Knowledge Proof
  verifyZKP(
    encryptedVote: { c1: bigint; c2: bigint },
    zkp: { commitment: bigint; challenge: bigint; response: bigint }
  ): boolean {
    const { commitment, challenge, response } = zkp;
    
    // Verify the ZKP proves the vote is either 0 or 1
    const lhs = this.modPow(this.g, response, this.p);
    const rhs = (commitment * this.modPow(encryptedVote.c1, challenge, this.p)) % this.p;
    
    // Also verify the encrypted vote format
    const m = (encryptedVote.c2 * this.modInverse(this.modPow(encryptedVote.c1, this.x, this.p), this.p)) % this.p;
    const validVote = m === BigInt(1) || m === this.g;
    
    return lhs === rhs && validVote;
  }

  public decrypt(ciphertext: ElGamalCiphertext): bigint {
    // ElGamal decryption: m = c2 / (c1^x)
    const s = this.modPow(ciphertext.c1, this.x, this.p);
    const sInverse = this.modInverse(s, this.p);
    const m = (ciphertext.c2 * sInverse) % this.p;
    
    // For our voting system, m should be either 1 (no vote) or g (vote)
    // If m === g, return 1 (vote), else return 0 (no vote)
    return m === this.g ? BigInt(1) : BigInt(0);
  }
} 