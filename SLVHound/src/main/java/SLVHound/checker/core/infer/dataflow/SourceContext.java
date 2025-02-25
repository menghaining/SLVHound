package SLVHound.checker.core.infer.dataflow;

import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;

public class SourceContext {
	private final BasicBlockInContext<IExplodedBasicBlock> block;
	private final AccessPath ap;

	/**
	 * differs where the source comes from.</br>
	 * "param": entry parameter</br>
	 * "findDB": the return of findDB</br>
	 * "session": the return of getsession
	 */
	String type = "param";

	public SourceContext(BasicBlockInContext<IExplodedBasicBlock> block, AccessPath ap, String type) {
		this.block = block;
		this.ap = ap;
		this.type = type;
	}

	public String getType() {
		return this.type;
	}

	public BasicBlockInContext<IExplodedBasicBlock> getBlock() {
		return block;
	}

	public AccessPath getAp() {
		return ap;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((ap == null) ? 0 : ap.hashCode());
		result = prime * result + ((block == null) ? 0 : block.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SourceContext other = (SourceContext) obj;
		if (ap == null) {
			if (other.ap != null)
				return false;
		} else if (!ap.equals(other.ap))
			return false;
		if (block == null) {
			if (other.block != null)
				return false;
		} else if (!block.equals(other.block))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "SourceContext [block=" + block + ", ap=" + ap + "]";
	}

}

