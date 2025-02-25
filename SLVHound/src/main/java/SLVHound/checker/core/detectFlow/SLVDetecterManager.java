package SLVHound.checker.core.detectFlow;

import java.util.HashSet;

import com.ibm.wala.dataflow.IFDS.ICFGSupergraph;
import com.ibm.wala.dataflow.IFDS.ISupergraph;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;

import SLVHound.checker.core.Util.RepoElement;

public class SLVDetecterManager {
	final ISupergraph<BasicBlockInContext<IExplodedBasicBlock>, CGNode> isg;
	boolean isForward = true;

	CallGraph cg;
	SLVDetecterFlowDomain<SLVDetecterDomainElement> domain;

	CGNode ASOEntry;
	HashSet<SSAInstruction> ASOs;
	
	 RepoElement authRepo;

	public SLVDetecterManager(CallGraph cg, CGNode entry, HashSet<SSAInstruction> aSOs, RepoElement authRepo) {
		this.cg = cg;
		ASOEntry = entry;
		ASOs = aSOs;
		this.authRepo=authRepo;

		isg = ICFGSupergraph.make(cg);
		domain = new SLVDetecterFlowDomain<SLVDetecterDomainElement>(SLVDetecterDomainElement.ZERO);
	}

	public boolean isForward() {
		return isForward;
	}

	public void setForward() {
		this.isForward = true;
	}

	public void setBackward() {
		this.isForward = false;
	}

	public ISupergraph<BasicBlockInContext<IExplodedBasicBlock>, CGNode> getIsg() {
		return isg;
	}

	public CallGraph getCg() {
		return cg;
	}

	public SLVDetecterFlowDomain<SLVDetecterDomainElement> getDomain() {
		return domain;
	}

	public CGNode getASOEntry() {
		return ASOEntry;
	}

	public HashSet<SSAInstruction> getASOs() {
		return ASOs;
	}
	
}
