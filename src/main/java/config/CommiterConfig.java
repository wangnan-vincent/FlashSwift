package config;

import commitment.BouncyCommiter;
import commitment.Commiter;

public class CommiterConfig {

	private static CommiterConfig INSTANCE;

	private Commiter commiter;

	private Key<?> key = new BouncyKey("secp256k1");

	private CommiterConfig() {
	}

	public void init(Key<?> key) {
		this.key = key;
		if (this.key instanceof BouncyKey) {
			this.commiter = new BouncyCommiter();
		} 
	}

	public static CommiterConfig getInstance() {
		if (INSTANCE == null) {
			INSTANCE = new CommiterConfig();
		}

		return INSTANCE;
	}

	public Commiter getCommiter() {
		return commiter;
	}

	public Key<?> getKey() {
		return key;
	}
}
