package zkp;

import java.io.Serializable;
import java.math.BigInteger;

import config.CommiterConfig;
import utils.SerializationUtils;

/**
 * 08-12-2020
 * 
 * @author nanwang
 *
 */
public abstract class ZKP implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	protected final BigInteger n = CommiterConfig.getInstance().getKey().getN();

	/**
	 * Verifies that the rehash of the particular variables is indeed the specified
	 * hash.
	 * 
	 * @return Description of this proof
	 */
	public abstract boolean verify();

	public byte[] toByteArray() {
		return SerializationUtils.toByteArray(this);
	}
}
