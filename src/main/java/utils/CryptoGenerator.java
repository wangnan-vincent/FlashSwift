package utils;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

/**
 * 08-12-2020
 * 
 * @author nanwang
 *
 */
public class CryptoGenerator {

	private static final Random RANDOM = new SecureRandom(BigInteger.ONE.toByteArray());
	
	private CryptoGenerator() {
	}

	/**
	 * Generate two prime numbers safely p and q = 2p+1
	 * 
	 * @param bitLength the number of bits required for the prime numbers
	 * @param seed
	 * @return
	 */
	public static BigInteger genSafePrimes(int bitLength) {
		BigInteger q = null;
		do {
			BigInteger p = BigInteger.probablePrime(bitLength,
					new SecureRandom(BigInteger.valueOf(new Random().nextLong()).toByteArray()));
			q = (p.shiftLeft(1)).add(BigInteger.ONE);
		} while (!q.isProbablePrime(50));

		return q;
	}

	public static BigInteger getRandomModQ(BigInteger q) {
		BigInteger r = new BigInteger(q.bitLength(), RANDOM);

		if (!inModQ(r, q)) {
			r = r.mod(q);
		}

		return r;
	}

	public static BigInteger getRandomWithBits(int nbits) {
		return new BigInteger(nbits, new Random());
	}

	public static BigInteger getRandomBeta(BigInteger q) {
		BigInteger r = null;

		do {
			r = new BigInteger(q.bitLength() - 4, new Random());
		} while (!inModQ(r, q));

		return r;
	}

	/**
	 * A special random number generator to find r in Z_q^*
	 * 
	 * @return a random integer less than q and relatively prime to q
	 */
	public static BigInteger getRandomModQStar(BigInteger q) {
		BigInteger r;
		do {
			r = new BigInteger(q.bitLength(), new Random());
		} while (!inModQStar(r, q));
		return r;
	}

	/**
	 * Checks if a given number is in Z_q^*.
	 * 
	 * Note that if a is zero, then the gcd(a,n) = gcd(0,n) = n, which is not one.
	 * 
	 * @param a the BigInteger we are checking
	 * @return 'true' if a is non-negative, less than q, and relatively prime to q
	 */
	public static boolean inModQStar(BigInteger a, BigInteger q) {
		return (a.gcd(q).equals(BigInteger.ONE) && inModQ(a, q));
	}

	/**
	 * Checks if a given number is in Z_q
	 * 
	 * @param a the BigInteger to be checked
	 * @param q the BigInteger modulus
	 * @return 'true' iff a is non-negative and less than q
	 */
	public static boolean inModQ(BigInteger a, BigInteger q) {
		return (a.compareTo(q) < 0 && a.compareTo(BigInteger.ZERO) >= 0);
	}
}
