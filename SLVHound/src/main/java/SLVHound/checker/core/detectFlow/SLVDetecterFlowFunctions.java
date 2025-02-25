package SLVHound.checker.core.detectFlow;

import com.ibm.wala.dataflow.IFDS.IFlowFunction;
import com.ibm.wala.dataflow.IFDS.IPartiallyBalancedFlowFunctions;
import com.ibm.wala.dataflow.IFDS.IUnaryFlowFunction;
import com.ibm.wala.dataflow.IFDS.IdentityFlowFunction;
import com.ibm.wala.dataflow.IFDS.TabulationDomain;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAInvokeInstruction;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.util.intset.IntSet;
import com.ibm.wala.util.intset.MutableSparseIntSet;

import SLVHound.checker.core.AuthenticationCheckModule;

public class SLVDetecterFlowFunctions
		implements IPartiallyBalancedFlowFunctions<BasicBlockInContext<IExplodedBasicBlock>> {
	TabulationDomain<SLVDetecterDomainElement, BasicBlockInContext<IExplodedBasicBlock>> domain;
	SLVDetecterManager manager;

	public SLVDetecterFlowFunctions(SLVDetecterManager manager) {
		this.domain = manager.domain;
		this.manager = manager;
	}

	@Override
	public IUnaryFlowFunction getNormalFlowFunction(BasicBlockInContext<IExplodedBasicBlock> src,
			BasicBlockInContext<IExplodedBasicBlock> dest) {
//		System.out.println("[FROM] " + src + " [TO] " + dest);

		return new IUnaryFlowFunction() {

			@Override
			public IntSet getTargets(int d1) {
				MutableSparseIntSet result = MutableSparseIntSet.makeEmpty();
				result.add(d1);
				return result;
			}

		};

	}

	@Override
	public IUnaryFlowFunction getCallFlowFunction(BasicBlockInContext<IExplodedBasicBlock> src,
			BasicBlockInContext<IExplodedBasicBlock> dest, BasicBlockInContext<IExplodedBasicBlock> ret) {
//		System.out.println("[FROM] " + src + " [TO] " + dest);
		return IdentityFlowFunction.identity();
	}

	@Override
	public IFlowFunction getReturnFlowFunction(BasicBlockInContext<IExplodedBasicBlock> call,
			BasicBlockInContext<IExplodedBasicBlock> src, BasicBlockInContext<IExplodedBasicBlock> dest) {
//		System.out.println("[FROM] " + src + " [TO] " + dest);
		return IdentityFlowFunction.identity();
	}

	@Override
	public IUnaryFlowFunction getCallToReturnFlowFunction(BasicBlockInContext<IExplodedBasicBlock> src,
			BasicBlockInContext<IExplodedBasicBlock> dest) {
//		System.out.println("[FROM] " + src + " [TO] " + dest);
		return new IUnaryFlowFunction() {

			@Override
			public IntSet getTargets(int d1) {
				MutableSparseIntSet result = MutableSparseIntSet.makeEmpty();
				result.add(d1);
				if (manager.isForward) {
					// gen session expire fact:
					if (d1 == 0) {
						SSAInstruction inst = src.getLastInstruction();
						if (inst instanceof SSAInvokeInstruction) {
							SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;
							if (AuthenticationCheckModule.isExpireOp(invoke, src.getNode(), manager.authRepo)) {
								SLVDetecterDomainElement ele = new SLVDetecterDomainElement(src.getNode(), inst,
										SLVDetecterDomainType.expire);
								int d = domain.add(ele);
								result.add(d);
							}
						}
					}
				} else {
					// gen ASO fact:
					if (d1 == 0) {
						SSAInstruction inst = src.getLastInstruction();
						if (inst instanceof SSAInvokeInstruction) {
							if (inst != null && manager.getASOs().contains(inst)) {
								SLVDetecterDomainElement ele = new SLVDetecterDomainElement(src.getNode(), inst,
										SLVDetecterDomainType.ASO);
								int d = domain.add(ele);
								result.add(d);
							}
						}
					}
				}

				return result;
			}

		};
	}

	@Override
	public IUnaryFlowFunction getCallNoneToReturnFlowFunction(BasicBlockInContext<IExplodedBasicBlock> src,
			BasicBlockInContext<IExplodedBasicBlock> dest) {
//		System.out.println("[FROM] " + src + " [TO] " + dest);
		return new IUnaryFlowFunction() {

			@Override
			public IntSet getTargets(int d1) {
				MutableSparseIntSet result = MutableSparseIntSet.makeEmpty();
				result.add(d1);
				if (manager.isForward) {
					// gen session expire fact:
					if (d1 == 0) {
						SSAInstruction inst = src.getLastInstruction();
						if (inst instanceof SSAInvokeInstruction) {
							SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;
							if (AuthenticationCheckModule.isExpireOp(invoke, src.getNode(), manager.authRepo)) {
								SLVDetecterDomainElement ele = new SLVDetecterDomainElement(src.getNode(), inst,
										SLVDetecterDomainType.expire);
								int d = domain.add(ele);
								result.add(d);
							}
						}
					}
				} else {
					// gen ASO fact
					if (d1 == 0) {
						SSAInstruction inst = src.getLastInstruction();
						if (inst instanceof SSAInvokeInstruction) {
							if (inst != null && manager.getASOs().contains(inst)) {
								SLVDetecterDomainElement ele = new SLVDetecterDomainElement(src.getNode(), inst,
										SLVDetecterDomainType.ASO);
								int d = domain.add(ele);
								result.add(d);
							}
						}
					}
				}

				return result;
			}

		};
	}

	@Override
	public IFlowFunction getUnbalancedReturnFlowFunction(BasicBlockInContext<IExplodedBasicBlock> src,
			BasicBlockInContext<IExplodedBasicBlock> dest) {
//		System.out.println("[FROM] " + src + " [TO] " + dest);
		return IdentityFlowFunction.identity();
	}

}
