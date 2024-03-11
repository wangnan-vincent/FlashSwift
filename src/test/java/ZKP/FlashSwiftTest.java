package ZKP;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.bouncycastle.math.ec.ECCurve;
import org.junit.Before;
import org.junit.Test;

import commitment.BouncyCommitment;
import commitment.Commiter;
import config.BouncyKey;
import config.CommiterConfig;
import structure.VectorP;
import zkp.TestConstants;
import zkp.range.flashswift.FlashSwift;

/**
 * 10-03-2024
 * 
 * @author nanwang
 *
 */
public class FlashSwiftTest {

	private Commiter commiter;

	private int instances = 1;

	@Before
	public void init() {
		CommiterConfig.getInstance().init(new BouncyKey("bn128"));
		this.commiter = CommiterConfig.getInstance().getCommiter();
	}

	@Test
	public void testFlashSwift() {

		int nbits = 32;
		int numberOfProofs = 1;

		int K = 3;
		int L = 11;

		BigInteger n = CommiterConfig.getInstance().getKey().getN();
		BigInteger q = CommiterConfig.getInstance().getKey().getQ();

		ECCurve curve = new ECCurve.Fp(q, BigInteger.ZERO, BigInteger.valueOf(3), n, null);

		VectorP gs = VectorP.from(IntStream.range(0, numberOfProofs * L)
				.mapToObj(i -> new BouncyCommitment(BouncyKey.mapIntoBN128(
						BigInteger.valueOf(String.valueOf(Math.random() + System.nanoTime()).hashCode()), curve, q)))
				.collect(Collectors.toList()));

		double log = Math.log(numberOfProofs * L) / Math.log(2);
		int size = 0;
		if (Math.ceil(log) > log) {
			size = (int) Math.ceil(log);
		} else {
			size = (int) log;
		}

		for (int i = 0; i < instances; i++) {
			List<BigInteger> xs = new LinkedList<>();
			for (int j = 0; j < numberOfProofs; j++) {
				xs.add(this.commiter.randWithBits(nbits));
			}

			FlashSwift zkp = new FlashSwift(xs, nbits, gs, K, L, (int) Math.pow(2, size));

			assertTrue(zkp.verify());

			FlashSwift.counter++;
		}

		System.out.println("FlashSwift Prove Time:" + FlashSwift.ptime / (instances - TestConstants.WARMUPS));
		System.out.println("FlashSwift Verify Time:" + FlashSwift.vtime / (instances - TestConstants.WARMUPS));
	}
}