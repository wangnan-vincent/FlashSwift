package zkp;

import commitment.Commiter;
import config.CommiterConfig;

/**
 * 
 * @author nanwang
 *
 */
public abstract class PedersenZKP extends ZKP {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	protected final Commiter commiter = CommiterConfig.getInstance().getCommiter();
}
