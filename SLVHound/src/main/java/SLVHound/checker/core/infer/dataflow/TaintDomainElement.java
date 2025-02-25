package SLVHound.checker.core.infer.dataflow;

import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ssa.SSAInstruction;

public class TaintDomainElement {
	public static TaintDomainElement ZERO = new TaintDomainElement(null, null, null, null);
	CGNode node;

	SSAInstruction currentInst;
	AccessPath ap;
	SourceContext source;

	public TaintDomainElement(CGNode node, SSAInstruction currentInst, AccessPath ap, SourceContext source) {
		this.node = node;
		this.currentInst = currentInst;
		this.ap = ap;
		this.source = source;
	}

	public AccessPath getAccessPath() {
		return ap;
	}

	public CGNode getNode() {
		return node;
	}

	public SSAInstruction getCurrentInst() {
		return currentInst;
	}

	public SourceContext getSource() {
		return source;
	}

}
