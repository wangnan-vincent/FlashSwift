package config;

import java.math.BigInteger;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import utils.CryptoGenerator;

public class BouncyKey extends Key<ECPoint> {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public BouncyKey(String keyName) {
		switch (keyName) {
		case "secp256k1":
		case "secp384r1":
		case "secp521r1":
			X9ECParameters parameters = CustomNamedCurves.getByName(keyName);
			this.g = parameters.getG();
			this.n = parameters.getN();
			this.h = this.g.multiply(CryptoGenerator.getRandomModQ(this.n));
			break;
		case "bn128":
			this.n = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
			this.q = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");
			ECCurve curve = new ECCurve.Fp(this.q, BigInteger.ZERO, BigInteger.valueOf(3), this.n, null);

			//this.g = curve.validatePoint(BigInteger.ONE, BigInteger.TWO);
			//this.h = curve.validatePoint(
			//		new BigInteger("9727523064272218541460723335320998459488975639302513747055235660443850046724"),
			//		new BigInteger("5031696974169251245229961296941447383441169981934237515842977230762345915487"));

			this.g = mapIntoBN128(BigInteger.valueOf(String.valueOf(Math.random()+System.nanoTime()).hashCode()), curve, this.q);
			this.h = mapIntoBN128(BigInteger.valueOf(String.valueOf(Math.random()).hashCode()), curve, this.q);
			
			break;
		}
	}

	public static ECPoint mapIntoBN128(BigInteger seed, ECCurve curve, BigInteger p) {

		seed = seed.mod(p);

		BigInteger y;

		seed = seed.subtract(BigInteger.ONE);
		do {
			seed = seed.add(BigInteger.ONE);
			BigInteger ySquared = seed.pow(3).add(BigInteger.valueOf(3)).mod(p);
			y = ySquared.modPow((p.add(BigInteger.ONE)).divide(BigInteger.valueOf(4)), p);
			if (y.modPow(BigInteger.valueOf(2), p).equals(ySquared)) {
				break;
			}
		} while (true);
		return curve.validatePoint(seed, y);
	}
}
