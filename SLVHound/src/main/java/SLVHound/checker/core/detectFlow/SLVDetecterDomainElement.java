package SLVHound.checker.core.detectFlow;

import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ssa.SSAInstruction;

public class SLVDetecterDomainElement {
	public static SLVDetecterDomainElement ZERO = new SLVDetecterDomainElement(null, null, SLVDetecterDomainType.zero);

	CGNode node;
	SSAInstruction currentInst;
	SLVDetecterDomainType type;

	public SLVDetecterDomainElement(CGNode node, SSAInstruction currentInst, SLVDetecterDomainType type) {
		this.node = node;
		this.currentInst = currentInst;
		this.type = type;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;

		if (obj instanceof SLVDetecterDomainElement) {
			SLVDetecterDomainElement obja = (SLVDetecterDomainElement) obj;
			if (node.equals(obja.node) && currentInst.equals(obja.currentInst) && type.equals(obja.type))
				return true;
		}

		return false;
	}

}
