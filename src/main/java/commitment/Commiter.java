package commitment;

import java.math.BigInteger;

import config.CommiterConfig;
import utils.CryptoGenerator;

public interface Commiter {

	public abstract Commitment commitTo(BigInteger x);

	public abstract Commitment commitTo(BigInteger x, BigInteger r);

	public abstract Commitment mulG(BigInteger x);

	public abstract Commitment mulH(BigInteger x);
	
	public abstract Commitment getG();
	
	public abstract Commitment getH();
	
	public abstract Commitment getIdentity();

	public default BigInteger rand() {
		return CryptoGenerator.getRandomModQ(CommiterConfig.getInstance().getKey().getN());
	}
	
	public default BigInteger randBy(BigInteger q) {
		return CryptoGenerator.getRandomModQ(q);
	}
	
	public default BigInteger randWithBits(int nbits) {
		return CryptoGenerator.getRandomWithBits(nbits);
	}
}
