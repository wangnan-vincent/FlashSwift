package zkp.range.flashswift;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

import commitment.Commitment;
import structure.VectorB;
import structure.VectorP;
import utils.HashUtils;
import zkp.PedersenZKP;
import zkp.TestConstants;

/**
 * 
 * @author nanwang
 * 10-03-2024
 */
public class FlashSwift extends PedersenZKP {

	private static final long serialVersionUID = 1L;

	private final List<Commitment> cxs = Lists.newLinkedList();
	private final List<Commitment> cts = new LinkedList<>();
	private List<BigInteger> vs;

	private final List<List<Commitment>> ws = new LinkedList<>();

	private final List<Commitment> cqs = new LinkedList<>();
	private final List<List<Commitment>> css = new LinkedList<>();

	private Commitment cQ;

	private final BigInteger u;

	private final VectorP gs;
	private final int nbits;
	private final int K;
	private final int L;
	private final int P;
	private final BigInteger TWO = BigInteger.TWO;
	private final int size;

	public static int counter = 0;
	public static long ptime = 0;
	public static long vtime = 0;

	public FlashSwift(List<BigInteger> xs, int nbits, VectorP gs, int K, int L, int P) {

		/****************************** Preprocessing ******************************/

		this.gs = gs;
		this.nbits = nbits;
		this.K = K;
		this.L = L;
		this.P = P;
		this.size = xs.size();

		List<BigInteger> TWOS = Lists.newLinkedList();
		for (int i = 0; i < this.nbits; i++) {
			TWOS.add(TWO.pow(i));
		}

		Map<Integer, List<List<BigInteger>>> bsMap = new HashMap<>();
		Map<Integer, List<List<BigInteger>>> bsrMap = new HashMap<>();
		Map<Integer, List<BigInteger>> rvsMap = new HashMap<>();
		List<List<BigInteger>> rss = Lists.newLinkedList();

		for (int j = 0; j < xs.size(); j++) {
			List<List<BigInteger>> bs = Lists.newLinkedList();
			List<List<BigInteger>> bsr = Lists.newLinkedList();
			List<BigInteger> rvs = Lists.newLinkedList();
			for (int i = 0; i < this.L; i++) {
				bs.add(new LinkedList<>());
				bsr.add(new LinkedList<>());
				rvs.add(this.commiter.rand());
			}
			bsMap.put(j, bs);
			bsrMap.put(j, bsr);
			rvsMap.put(j, rvs);

			this.css.add(Lists.newLinkedList());
			rss.add(Lists.newLinkedList());
		}

		List<BigInteger> rts = Lists.newLinkedList();
		List<BigInteger> rqs = Lists.newLinkedList();
		List<BigInteger> r2s = Lists.newLinkedList();
		List<BigInteger> betas = Lists.newLinkedList();
		List<BigInteger> doubleBetas = Lists.newLinkedList();
		List<List<BigInteger>> ds = Lists.newLinkedList();
		Set<Integer> set = new HashSet<>();
		for (int i = 0; i < this.K; i++) {
			ds.add(new LinkedList<>());
			set.add(i);

			BigInteger rq = this.commiter.rand();
			rqs.add(rq);
			this.cqs.add(this.commiter.mulH(rq));
		}

		List<Set<Integer>> combinations = Sets.combinations(set, 2).stream().collect(Collectors.toList());

		for (int i = 0; i < combinations.size(); i++) {
			BigInteger rt = this.commiter.rand();
			rts.add(rt);
			this.cts.add(this.commiter.mulH(rt));
		}

		for (int i = 0; i < xs.size(); i++) {
			r2s.addAll(rvsMap.get(i).stream().map(r -> r.pow(2).negate().mod(this.n)).collect(Collectors.toList()));
		}

		BigInteger rq = this.commiter.rand();
		rqs.add(rq);
		this.cQ = this.gs.mulBAndSum(VectorB.from(r2s, this.n)).add(this.commiter.mulH(rq));

		for (int i = 0; i < this.size; i++) {
			for (int k = 0; k < this.K - 1; k++) {
				BigInteger r = this.commiter.rand();
				rss.get(i).add(r);
				this.css.get(i).add(this.commiter.mulH(r));
			}
		}

		List<BigInteger> rxs = Lists.newLinkedList();
		for (int i = 0; i < this.size; i++) {
			BigInteger rx = this.commiter.rand();
			rxs.add(rx);
			this.cxs.add(this.commiter.commitTo(xs.get(i), rx));
		}

		List<Commitment> cssForKs = Lists.newLinkedList();
		for (int i = 0; i < this.size; i++) {
			cssForKs.add(this.commiter
					.mulG(rvsMap.get(i).stream().reduce(BigInteger.ZERO, (r1, r2) -> r1.add(r2)).mod(this.n)));
		}

		/****************************** Preprocessing ******************************/

		long s = System.nanoTime();

		for (int j = 0; j < this.size; j++) {
			BigInteger x = xs.get(j);
			for (int i = 0; i < this.L * this.K; i++) {
				BigInteger b = x.testBit(i) ? BigInteger.ONE : BigInteger.ZERO;
				int idx = i / this.K;
				int mod = i % this.K;
				if (i < this.nbits) {
					BigInteger two = TWOS.get(i);
					BigInteger btwo = b.multiply(two);
					bsMap.get(j).get(idx).add(btwo);
					bsrMap.get(j).get(idx).add(BigInteger.ONE.subtract(b).multiply(two));
					ds.get(mod).add(btwo);
				} else {
					bsMap.get(j).get(idx).add(BigInteger.ZERO);
					bsrMap.get(j).get(idx).add(BigInteger.ZERO);
					ds.get(mod).add(BigInteger.ZERO);
				}
			}
		}

		for (int i = 0; i < combinations.size(); i++) {
			List<Integer> l = Lists.newLinkedList(combinations.get(i));
			int idx1 = l.get(0);
			int idx2 = l.get(1);

			List<BigInteger> ts = Lists.newLinkedList();
			for (int k = 0; k < this.size; k++) {
				List<List<BigInteger>> bs = bsMap.get(k);
				List<List<BigInteger>> bsr = bsrMap.get(k);
				for (int j = 0; j < this.L; j++) {
					List<BigInteger> bl = bs.get(j);
					List<BigInteger> bsl = bsr.get(j);

					BigInteger t = bl.get(idx1).multiply(bsl.get(idx2));
					t = t.add(bl.get(idx2).multiply(bsl.get(idx1)));
					ts.add(t);
				}
			}
			this.cts.set(i, this.cts.get(i).add(this.gs.mulBAndSum(VectorB.from(ts, this.n))));
		}

		for (int i = 0; i < this.K; i++) {
			List<BigInteger> ls = Lists.newLinkedList();
			for (int k = 0; k < this.size; k++) {
				List<List<BigInteger>> bs = bsMap.get(k);
				List<List<BigInteger>> bsr = bsrMap.get(k);
				List<BigInteger> rvs = rvsMap.get(k);
				for (int j = 0; j < this.L; j++) {
					BigInteger t = rvs.get(j).multiply(bsr.get(j).get(i).subtract(bs.get(j).get(i)));
					ls.add(t);
				}

				if (i < this.K - 1) {
					BigInteger d = ds.get(i).subList(this.L * k, this.L * (k + 1)).stream()
							.reduce(BigInteger.ZERO, (d1, d2) -> d1.add(d2)).mod(this.n);
					this.css.get(k).set(i, this.css.get(k).get(i).add(this.commiter.mulG(d)));
				}
			}

			this.cqs.set(i, this.cqs.get(i).add(this.gs.mulBAndSum(VectorB.from(ls, this.n))));
		}

		List<Commitment> commitments = Lists.newLinkedList();
		commitments.addAll(this.cxs);
		commitments.addAll(this.cts);
		commitments.addAll(this.cqs);
		commitments.addAll(this.css.stream().flatMap(l -> l.stream()).collect(Collectors.toList()));

		BigInteger y = HashUtils.hash(commitments).mod(this.n);
		VectorB ys = VectorB.powerNWithSeed(this.size, y, y, this.n);

		this.cQ = this.cQ.add(VectorP.from(cssForKs).mulBAndSum(ys));

		BigInteger beta = HashUtils.hash(Arrays.asList(this.cQ), y).mod(this.n);
		betas.add(beta);
		int count = 1;
		while (count < this.K) {
			beta = HashUtils.hash(beta).mod(this.n);
			betas.add(beta);
			count++;
		}

		List<BigInteger> vl = Lists.newLinkedList();
		List<BigInteger> fl = Lists.newLinkedList();
		for (int i = 0; i < this.size; i++) {
			for (int j = 0; j < this.L; j++) {
				BigInteger v = rvsMap.get(i).get(j);

				BigInteger f = BigInteger.ZERO;
				int base = j * this.K;
				for (int k = 0; k < this.K; k++) {
					int idx = base + k;
					v = v.add(bsMap.get(i).get(j).get(k).multiply(betas.get(k)));
					if (idx < this.nbits) {
						f = f.add(betas.get(k).multiply(TWOS.get(idx)));
					}
				}
				fl.add(f.mod(this.n));
				vl.add(v.mod(this.n));
			}
		}

		// pad zeros
		while (vl.size() < this.P) {
			vl.add(BigInteger.ZERO);
		}

		for (int i = 0; i < combinations.size(); i++) {
			List<Integer> l = Lists.newLinkedList(combinations.get(i));
			doubleBetas.add(betas.get(l.get(0)).multiply(betas.get(l.get(1))).mod(this.n));
		}

		BigInteger localU = BigInteger.ZERO;
		for (int i = 0; i < combinations.size(); i++) {
			localU = localU.add(rts.get(i).multiply(doubleBetas.get(i)));
		}
		for (int i = 0; i < this.K; i++) {
			localU = localU.add(rqs.get(i).multiply(betas.get(i)));
		}
		localU = localU.add(rq);

		BigInteger lastBeta = betas.get(this.K - 1);
		for (int i = 0; i < this.size; i++) {
			List<BigInteger> rl = rss.get(i);
			BigInteger tmp = BigInteger.ZERO;
			for (int j = 0; j < this.K - 1; j++) {
				tmp = tmp.add(rl.get(j).multiply(betas.get(j).subtract(lastBeta)));
			}
			tmp = tmp.add(rxs.get(i).multiply(lastBeta));
			localU = localU.add(tmp.multiply(ys.getList().get(i)));
		}
		this.u = localU.mod(this.n);

		List<Commitment> gl = Lists.newLinkedList();
		for (int i = 0; i < this.size; i++) {
			Commitment gy = this.commiter.mulG(ys.getList().get(i));
			for (int j = 0; j < this.L; j++) {
				gl.add(gy);
			}
		}

		if (vl.size() > 8) {
			// pad zeros
			VectorP gprimes = this.gs.mulB(VectorB.from(fl, this.n)).padZeros(this.P);
			VectorP glprimes = VectorP.from(gl).padZeros(this.P);
			VectorP gsprimes = this.gs.padZeros(this.P);

			compress(VectorB.from(vl, this.n), gprimes.addP(glprimes), gsprimes, beta);
		} else {
			this.vs = vl;
		}

		long e = System.nanoTime();

		if (counter >= TestConstants.WARMUPS) {
			ptime += (e - s);
		}
	}

	public void compress(VectorB xs, VectorP gs, VectorP hs, BigInteger challenge) {

		int size = xs.getList().size();
		if (size == 8) {
			this.vs = xs.getList();
			return;
		}

		int halfSize = size / 2;

		VectorP gL = gs.subVector(0, halfSize);
		VectorP gR = gs.subVector(halfSize, size);

		VectorP hL = hs.subVector(0, halfSize);
		VectorP hR = hs.subVector(halfSize, size);

		VectorB xL = xs.subVector(0, halfSize);
		VectorB xR = xs.subVector(halfSize, size);

		VectorB hadamardProd = xL.hadamardProd(xR).mulConstant(TWO.negate());

		Commitment A = hR.mulBAndSum(xL.hadamardProd(xL).negate());
		Commitment B = gR.mulBAndSum(xL).add(hR.mulBAndSum(hadamardProd));
		Commitment D = gL.mulBAndSum(xR).add(hL.mulBAndSum(hadamardProd));
		Commitment E = hL.mulBAndSum(xR.hadamardProd(xR).negate());

		List<Commitment> l = Arrays.asList(A, B, D, E);
		this.ws.add(l);

		BigInteger c = HashUtils.hash(l, challenge).mod(this.n);

		VectorB zl = xL.add(xR.mulConstant(c));

		BigInteger cinv = c.modInverse(this.n);
		BigInteger c2inv = cinv.multiply(cinv).mod(this.n);

		VectorP gprime = gL.addP(gR.mulB(cinv));
		VectorP hprime = hL.addP(hR.mulB(c2inv));

		compress(zl, gprime, hprime, c);
	}

	@Override
	public boolean verify() {

		List<BigInteger> TWOS = Lists.newLinkedList();
		for (int i = 0; i < this.nbits; i++) {
			TWOS.add(TWO.pow(i));
		}

		Set<Integer> set = new HashSet<>();
		for (int i = 0; i < this.K; i++) {
			set.add(i);
		}
		List<Set<Integer>> combinations = Sets.combinations(set, 2).stream().collect(Collectors.toList());

		List<BigInteger> doubleBetas = Lists.newLinkedList();
		List<BigInteger> betas = Lists.newLinkedList();

		long s = System.nanoTime();

		List<Commitment> commitments = Lists.newLinkedList();
		commitments.addAll(this.cxs);
		commitments.addAll(this.cts);
		commitments.addAll(this.cqs);
		commitments.addAll(this.css.stream().flatMap(l -> l.stream()).collect(Collectors.toList()));

		BigInteger y = HashUtils.hash(commitments).mod(this.n);
		VectorB ys = VectorB.powerNWithSeed(this.size, y, y, this.n);

		BigInteger beta = HashUtils.hash(Arrays.asList(this.cQ), y).mod(this.n);
		betas.add(beta);
		int count = 1;
		while (count < this.K) {
			beta = HashUtils.hash(beta).mod(this.n);
			betas.add(beta);
			count++;
		}

		for (int i = 0; i < combinations.size(); i++) {
			List<Integer> l = Lists.newLinkedList(combinations.get(i));
			doubleBetas.add(betas.get(l.get(0)).multiply(betas.get(l.get(1))).mod(this.n));
		}

		Commitment F = this.commiter.mulH(this.u.negate().mod(this.n)).add(this.cQ);
		for (int i = 0; i < combinations.size(); i++) {
			F = F.add(this.cts.get(i).mul(doubleBetas.get(i)));
		}

		for (int i = 0; i < this.K; i++) {
			F = F.add(this.cqs.get(i).mul(betas.get(i)));
		}

		BigInteger lastBeta = betas.get(this.K - 1);
		for (int i = 0; i < this.size; i++) {
			BigInteger challenge = ys.getList().get(i);
			Commitment localret = this.commiter.getIdentity();
			List<Commitment> localCSS = this.css.get(i);
			for (int j = 0; j < this.K - 1; j++) {
				localret = localret
						.add(localCSS.get(j).mul(betas.get(j).subtract(lastBeta).multiply(challenge).mod(this.n)));
			}
			F = F.add(localret).add(this.cxs.get(i).mul(lastBeta.multiply(challenge).mod(this.n)));
		}

		List<BigInteger> challenges = Lists.newLinkedList();
		BigInteger challenge = beta;
		for (int i = 0; i < this.ws.size(); i++) {
			List<Commitment> elements = this.ws.get(i);
			Commitment A = elements.get(0);
			Commitment B = elements.get(1);
			Commitment D = elements.get(2);
			Commitment E = elements.get(3);

			BigInteger c = HashUtils.hash(Arrays.asList(A, B, D, E), challenge).mod(this.n);
			challenge = c;
			BigInteger c2 = c.multiply(c).mod(this.n);
			BigInteger cinv = c.modInverse(this.n);
			BigInteger c2inv = cinv.multiply(cinv).mod(this.n);

			F = A.mul(c2inv).add(B.mul(cinv)).add(F).add(D.mul(c)).add(E.mul(c2));

			challenges.add(cinv);
		}

		List<BigInteger> fl = Lists.newLinkedList();
		for (int i = 0; i < this.size; i++) {
			for (int j = 0; j < this.L; j++) {
				BigInteger f = BigInteger.ZERO;
				int base = j * this.K;
				for (int k = 0; k < this.K; k++) {
					int idx = base + k;
					if (idx < this.nbits) {
						f = f.add(betas.get(k).multiply(TWOS.get(idx)));
					}
				}
				fl.add(f.mod(this.n));
			}
		}

		List<BigInteger> exponents0 = Lists.newLinkedList();
		List<Map<Integer, BigInteger>> exponents1 = Lists.newLinkedList();
		List<Map<Integer, BigInteger>> exponents2 = Lists.newLinkedList();

		for (int i = 0; i < this.size; i++) {
			BigInteger initialExpo = ys.getList().get(i);

			int base = i * this.L;
			for (int j = 0; j < this.L; j++) {
				int idx = base + j;

				Map<Integer, BigInteger> map1 = new HashMap<>();
				Map<Integer, BigInteger> map2 = new HashMap<>();
				map1.put(idx, fl.get(idx));
				map2.put(idx, BigInteger.ONE);
				exponents0.add(initialExpo);
				exponents1.add(map1);
				exponents2.add(map2);
			}
		}

		int cou = exponents0.size();
		while (exponents0.size() < this.P) {
			exponents0.add(BigInteger.ZERO);
			Map<Integer, BigInteger> map1 = new HashMap<>();
			Map<Integer, BigInteger> map2 = new HashMap<>();
			map1.put(cou, BigInteger.ONE);
			map2.put(cou, BigInteger.ONE);
			exponents1.add(map1);
			exponents2.add(map2);
		}

		for (int i = 0; i < challenges.size(); i++) {
			BigInteger cinv = challenges.get(i);
			BigInteger cinv2 = cinv.multiply(cinv).mod(this.n);
			exponents0 = halve0(exponents0, cinv);
			exponents1 = halve1(exponents1, cinv);
			exponents2 = halve1(exponents2, cinv2);
		}

		BigInteger finalExpo0 = BigInteger.ZERO;

		Map<Integer, BigInteger> finalExpo1 = new HashMap<>();
		for (int i = 0; i < exponents1.size(); i++) {
			BigInteger z = this.vs.get(i);
			finalExpo0 = finalExpo0.add(exponents0.get(i).multiply(z));

			BigInteger z2 = z.multiply(z).negate().mod(this.n);
			Map<Integer, BigInteger> map1 = exponents1.get(i);
			Map<Integer, BigInteger> map2 = exponents2.get(i);

			for (int key : map1.keySet()) {
				BigInteger v1 = map1.get(key).multiply(z);
				BigInteger v2 = map2.get(key).multiply(z2);

				finalExpo1.put(key, v1.add(v2).mod(this.n));
			}
		}
		finalExpo0 = finalExpo0.mod(this.n);

		VectorP gsprimes = this.gs.padZeros(this.P);
		Commitment ret = this.commiter.mulG(finalExpo0);
		for (int key : finalExpo1.keySet()) {
			ret = ret.add(gsprimes.getList().get(key).mul(finalExpo1.get(key)));
		}
		boolean b = ret.equals(F);

		long e = System.nanoTime();

		if (counter >= TestConstants.WARMUPS) {
			vtime += (e - s);
		}

		return b;
	}

	private List<BigInteger> halve0(List<BigInteger> exponents, BigInteger val) {

		int halfsize = exponents.size() / 2;

		List<BigInteger> ret = Lists.newLinkedList();
		for (int i = 0; i < halfsize; i++) {
			BigInteger left = exponents.get(i);
			BigInteger right = exponents.get(i + halfsize).multiply(val);

			ret.add(left.add(right).mod(this.n));
		}

		return ret;
	}

	private List<Map<Integer, BigInteger>> halve1(List<Map<Integer, BigInteger>> exponents, BigInteger val) {

		int halfsize = exponents.size() / 2;
		for (int i = 0; i < halfsize; i++) {
			Map<Integer, BigInteger> leftMap = exponents.get(i);
			Map<Integer, BigInteger> rightMap = exponents.get(i + halfsize);
			for (Map.Entry<Integer, BigInteger> entry : rightMap.entrySet()) {
				leftMap.put(entry.getKey(), entry.getValue().multiply(val).mod(this.n));
			}
		}

		return exponents.subList(0, halfsize);
	}
}
