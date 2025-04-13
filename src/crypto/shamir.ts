import crypto from 'crypto';

export class ShamirSecretSharing {
  private prime: bigint = BigInt('115792089237316195423570985008687907853269984665640564039457584007913129639747');

  constructor(private threshold: number, private totalShares: number) {
    if (threshold > totalShares) throw new Error('Threshold cannot be greater than total shares');
  }

  private generatePolynomial(secret: bigint): bigint[] {
    const coefficients: bigint[] = [secret];
    for (let i = 1; i < this.threshold; i++) {
      coefficients.push(this.generateRandomBigInt());
    }
    return coefficients;
  }

  private generateRandomBigInt(): bigint {
    const bytes = crypto.randomBytes(32);
    return BigInt('0x' + bytes.toString('hex')) % this.prime;
  }

  createShares(secret: bigint): Map<number, bigint> {
    const coefficients = this.generatePolynomial(secret);
    const shares = new Map<number, bigint>();

    for (let x = 1; x <= this.totalShares; x++) {
      let y = coefficients[0];
      let pow = BigInt(1);
      
      for (let i = 1; i < coefficients.length; i++) {
        pow = (pow * BigInt(x)) % this.prime;
        y = (y + (coefficients[i] * pow)) % this.prime;
      }
      
      shares.set(x, y);
    }

    return shares;
  }

  reconstructSecret(shares: Map<number, bigint>): bigint {
    if (shares.size < this.threshold) {
      throw new Error('Not enough shares to reconstruct the secret');
    }

    let secret = BigInt(0);
    const points = Array.from(shares.entries());

    for (let i = 0; i < this.threshold; i++) {
      let numerator = BigInt(1);
      let denominator = BigInt(1);

      for (let j = 0; j < this.threshold; j++) {
        if (i !== j) {
          const [x_i, _y1] = points[i];
          const [x_j, _y2] = points[j];
          numerator = (numerator * BigInt(-x_j)) % this.prime;
          denominator = (denominator * BigInt(x_i - x_j)) % this.prime;
        }
      }

      const [_, y_i] = points[i];
      const term = (y_i * numerator * this.modInverse(denominator)) % this.prime;
      secret = (secret + term) % this.prime;
    }

    return (secret + this.prime) % this.prime;
  }

  private modInverse(a: bigint): bigint {
    const b = this.prime;
    let [old_r, r] = [a, b];
    let [old_s, s] = [BigInt(1), BigInt(0)];

    while (r !== BigInt(0)) {
      const quotient = old_r / r;
      [old_r, r] = [r, old_r - quotient * r];
      [old_s, s] = [s, old_s - quotient * s];
    }

    return (old_s + this.prime) % this.prime;
  }
} 