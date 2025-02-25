package SLVHound.checker.core.infer.dataflow;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.dataflow.IFDS.IFlowFunction;
import com.ibm.wala.dataflow.IFDS.IPartiallyBalancedFlowFunctions;
import com.ibm.wala.dataflow.IFDS.IUnaryFlowFunction;
import com.ibm.wala.dataflow.IFDS.IdentityFlowFunction;
import com.ibm.wala.dataflow.IFDS.TabulationDomain;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ssa.SSAArrayLoadInstruction;
import com.ibm.wala.ssa.SSAGetInstruction;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAInvokeInstruction;
import com.ibm.wala.ssa.SSAPutInstruction;
import com.ibm.wala.ssa.SSAReturnInstruction;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.types.FieldReference;
import com.ibm.wala.util.intset.IntSet;
import com.ibm.wala.util.intset.MutableSparseIntSet;


public class TaintFlowFunctions implements IPartiallyBalancedFlowFunctions<BasicBlockInContext<IExplodedBasicBlock>> {
	TabulationDomain<TaintDomainElement, BasicBlockInContext<IExplodedBasicBlock>> domain;
	TaintManager manager;

	public TaintFlowFunctions(TaintManager manager) {
		this.domain = manager.domain;
		this.manager = manager;

	}

	@Override
	public IUnaryFlowFunction getNormalFlowFunction(BasicBlockInContext<IExplodedBasicBlock> src,
			BasicBlockInContext<IExplodedBasicBlock> dest) {

		return new IUnaryFlowFunction() {

			@Override
			public IntSet getTargets(int d1) {
				MutableSparseIntSet result = MutableSparseIntSet.makeEmpty();

				CGNode node = src.getNode();
				SSAInstruction inst = src.getLastInstruction();
				TaintDomainElement de = domain.getMappedObject(d1);
				AccessPath ap = de.getAccessPath();

				if (inst instanceof SSAArrayLoadInstruction) {
					result.add(d1);
					SSAArrayLoadInstruction instruction = (SSAArrayLoadInstruction) inst;

					int arrayRef = instruction.getArrayRef();
					if (ap.getBase() == arrayRef) {
						AccessPath newAP = new AccessPath(instruction.getDef(), ap.cloneFieldRefs(), node);
						result.add(domain.add(new TaintDomainElement(node, instruction, newAP, de.getSource())));
					}
				} else if (inst instanceof SSAReturnInstruction) {
					result.add(d1);
					SSAReturnInstruction instruction = (SSAReturnInstruction) inst;
					if (!instruction.returnsVoid()) {
						int x = instruction.getResult();
						if (ap.getBase() == x) {
							result.add(
									domain.add(new TaintDomainElement(node, instruction, ap.clone(), de.getSource())));
						}
					}
				} else if (inst instanceof SSAGetInstruction) {
					result.add(d1);
					SSAGetInstruction instruction = (SSAGetInstruction) inst;

					int refVn = instruction.getRef();
					int defVn = instruction.getDef();
					// if base == left, then kill
					if (ap.getBase() != defVn) {
						result.add(d1);
						if (instruction.isStatic()) {
							// a = B.f; incoming B.f.g, then taint a.g
							if (ap.isStatic()) {
								AccessPath newAP = new AccessPath(defVn, ap.cutFirstField(), node);
								result.add(
										domain.add(new TaintDomainElement(node, instruction, newAP, de.getSource())));
							}
						} else {
							if (ap.getBase() == refVn) {
								AccessPath newAP = new AccessPath(defVn, ap.cutFirstField(), node);
								result.add(
										domain.add(new TaintDomainElement(node, instruction, newAP, de.getSource())));
							}
						}
					}
				} else if (inst instanceof SSAPutInstruction) {
					SSAPutInstruction instruction = (SSAPutInstruction) inst;
					int val = instruction.getVal();
					int refVn = instruction.getRef();
					FieldReference fldRef = instruction.getDeclaredField();

					if (ap.getBase() == val) {
						AccessPath newAP = new AccessPath(refVn, ap.appendFirstField(fldRef), node);
						int fact = domain.add(new TaintDomainElement(node, instruction, newAP, de.getSource()));
						result.add(fact);
						result.add(d1);
					} else {
						FieldReference firstField = ap.getFirstField();
						// b.f=a; incoming b.f or b.f.g, then kill
						if (ap.getBase() == instruction.getRef() && firstField != null
								&& Util.isCommonField(manager.callgraph.getClassHierarchy(), fldRef, firstField)) {
							// kill;
						} else {
							result.add(d1);
						}
					}
				} else {
					result.add(d1);
					int n = inst.getNumberOfUses();
					for (int i = 0; i < n; ++i) {
						int use = inst.getUse(i);
						if (use == ap.getBase()) {
							int def = inst.getDef();
							AccessPath newAP = new AccessPath(def, ap.cloneFieldRefs(), node);
							result.add(domain.add(new TaintDomainElement(node, inst, newAP, de.getSource())));
							break;
						}
					}
				}

				return result;
			}

		};

	}

	@Override
	public IUnaryFlowFunction getCallFlowFunction(BasicBlockInContext<IExplodedBasicBlock> src,
			BasicBlockInContext<IExplodedBasicBlock> dest, BasicBlockInContext<IExplodedBasicBlock> ret) {
		SSAInvokeInstruction invokeInst = (SSAInvokeInstruction) src.getLastInstruction();

		Map<Integer, Set<Integer>> actualToParam = new HashMap<Integer, Set<Integer>>();
		int numActuals = invokeInst.getNumberOfUses();

		for (int i = 0; i < numActuals; ++i) {
			Set<Integer> values = actualToParam.get(invokeInst.getUse(i));
			if (values == null) {
				values = new HashSet<Integer>();
				actualToParam.put(invokeInst.getUse(i), values);
			}
			values.add(i + 1);
		}

		return new IUnaryFlowFunction() {

			@Override
			public IntSet getTargets(int d1) {
				MutableSparseIntSet result = MutableSparseIntSet.makeEmpty();

				if (d1 == 0) {
					if (manager.getAuthenticationParamSourceMethods().contains(dest.getMethod().getSignature())) {
						int i = 2;
						if (dest.getMethod().isStatic())
							i = 1;
						for (; i <= dest.getMethod().getNumberOfParameters(); i++) {
							AccessPath ap = new AccessPath(i, null, dest.getNode());
							TaintDomainElement mElement = new TaintDomainElement(dest.getNode(), null, ap,
									new SourceContext(dest, ap, "param"));
							int idx = domain.add(mElement);
							if (idx >= 0) {
								result.add(idx);
							}
						}
					}
					result.add(0);
				} else {
					result.add(d1);
					TaintDomainElement de = domain.getMappedObject(d1);
					AccessPath ap = de.getAccessPath();
					if (ap.isStatic()) {
						result.add(d1);
					} else if (actualToParam.containsKey(ap.getBase())) {
						Set<Integer> params = actualToParam.get(ap.getBase());
						if (params != null) {
							for (Integer param : params) {
								AccessPath newAP = new AccessPath(param, ap.cloneFieldRefs(), dest.getNode());
								int idx = domain.add(new TaintDomainElement(src.getNode(),
										src.getDelegate().getInstruction(), newAP, de.getSource()));
								result.add(idx);
							}
						}
					}
				}
				return result;
			}

		};
	}

	@Override
	public IFlowFunction getReturnFlowFunction(BasicBlockInContext<IExplodedBasicBlock> call,
			BasicBlockInContext<IExplodedBasicBlock> src, BasicBlockInContext<IExplodedBasicBlock> dest) {
		SSAInvokeInstruction invokeInst = (SSAInvokeInstruction) call.getLastInstruction();
		IMethod method = src.getMethod();

		Map<Integer, Integer> paramToActual = new HashMap<Integer, Integer>();
		int numActuals = invokeInst.getNumberOfUses();
		int numUse = invokeInst.getNumberOfUses();
		for (int i = 0; i < numActuals; ++i) {
			if (i < numUse)
				paramToActual.put(i + 1, invokeInst.getUse(i));
		}

		return new IUnaryFlowFunction() {

			@Override
			public IntSet getTargets(int d1) {
				MutableSparseIntSet result = MutableSparseIntSet.makeEmpty();
				if (d1 == 0) {
					result.add(0);
				} else {
					result.add(d1);
					TaintDomainElement de = domain.getMappedObject(d1);
					AccessPath ap = de.getAccessPath();
					if (ap.isStatic()) {
						result.add(d1);
					} else {
						if ((paramToActual.containsKey(ap.getBase())
								&& method.getParameterType(ap.getBase() - 1).isReferenceType())
								|| (ap.getBase() <= 1 && paramToActual.containsKey(ap.getBase()))) {
							int vn = paramToActual.get(ap.getBase());
							AccessPath newAP = new AccessPath(vn, ap.cloneFieldRefs(), dest.getNode());
							int idx = domain.add(new TaintDomainElement(call.getNode(),
									call.getDelegate().getInstruction(), newAP, de.getSource()));
							result.add(idx);
						}
					}
				}
				return result;
			}
		};

	}

	@Override
	public IUnaryFlowFunction getCallToReturnFlowFunction(BasicBlockInContext<IExplodedBasicBlock> src,
			BasicBlockInContext<IExplodedBasicBlock> dest) {

		return new IUnaryFlowFunction() {

			@Override
			public IntSet getTargets(int d1) {
				MutableSparseIntSet result = MutableSparseIntSet.makeEmpty();
				if (d1 == 0) {
					result.add(0);
					/**
					 * if the callee is in sources, gen new taint of its define value.
					 */
					// add authentication session source
					if (manager.getAuthenticationSessionSrcs().contains(src)) {
						int idx = Util.genSourceForRetValue(domain, src, "session");
						result.add(idx);
					}
					// add the return value of save db as sources
					if (manager.getAuthenticationFindDBSrc().contains(src)) {
						int idx = Util.genSourceForRetValue(domain, src, "findDB");
						result.add(idx);
					}
				} else {
					result.add(d1);
				}

				return result;
			}

		};
	}

	@Override
	public IUnaryFlowFunction getCallNoneToReturnFlowFunction(BasicBlockInContext<IExplodedBasicBlock> src,
			BasicBlockInContext<IExplodedBasicBlock> dest) {
		return new IUnaryFlowFunction() {

			@Override
			public IntSet getTargets(int d1) {
				MutableSparseIntSet result = MutableSparseIntSet.makeEmpty();
				if (d1 == 0) {
					result.add(0);
					/**
					 * if the callee is in sources, gen new taint of its define value.
					 */
					// add authentication session source
					if (manager.getAuthenticationSessionSrcs().contains(src)) {
						int idx = Util.genSourceForRetValue(domain, src, "session");
						result.add(idx);
					}
					// add the return value of save db as sources
					if (manager.getAuthenticationFindDBSrc().contains(src)) {
						int idx = Util.genSourceForRetValue(domain, src, "findDB");
						result.add(idx);
					}
				} else {
					result.add(d1);
				}

				return result;
			}

		};
	}

	@Override
	public IFlowFunction getUnbalancedReturnFlowFunction(BasicBlockInContext<IExplodedBasicBlock> src,
			BasicBlockInContext<IExplodedBasicBlock> dest) {
		return IdentityFlowFunction.identity();
	}

}
