export type BigInteger = bigint;

export function modInv(a: bigint, m: bigint): bigint {
  let [old_r, r] = [a, m];
  let [old_s, s] = [BigInt(1), BigInt(0)];

  while (r !== BigInt(0)) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }

  return (old_s + m) % m;
}

export function lagrangeInterpolation(index: number, indices: number[], p: bigint): bigint {
  let result = BigInt(1);
  const x = BigInt(index);

  for (const j of indices) {
    if (index === j) continue;
    const xj = BigInt(j);
    const num = (BigInt(0) - xj) % p;
    const den = modInv((x - xj + p) % p, p);
    result = (result * num * den) % p;
  }

  return result;
} 