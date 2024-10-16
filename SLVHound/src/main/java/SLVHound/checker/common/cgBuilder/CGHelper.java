package SLVHound.checker.common.cgBuilder;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Set;

import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.impl.Everywhere;
import com.ibm.wala.ipa.callgraph.impl.ExplicitCallGraph;
import com.ibm.wala.ipa.callgraph.impl.ExplicitCallGraph.ExplicitNode;
import com.ibm.wala.ipa.callgraph.propagation.SSAPropagationCallGraphBuilder;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAInvokeInstruction;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.util.CancelException;

public class CGHelper {

	/**
	 * for the node not in current CG, also create one to return. BUT, add the
	 * created node into CG
	 */
	public static Set<CGNode> findAllTargets(SSAInvokeInstruction invoke, CGNode ep, CallGraph cg) {
		Set<CGNode> targetNodes = new HashSet<>();
		IClass clazz = cg.getClassHierarchy().lookupClass(invoke.getDeclaredTarget().getDeclaringClass());
		if (clazz == null)
			return targetNodes;
		IMethod targetMtd = clazz.getMethod(invoke.getDeclaredTarget().getSelector());
		if (targetMtd == null) {
			if (clazz.isInterface()) {
				// a extends A implement clazz
				// invoke: clazz.foo()
				// foo define in A
				Collection<IClass> subs = cg.getClassHierarchy().getImplementors(clazz.getReference());
				if (subs != null)
					for (IClass sub : subs) {
						IMethod m = sub.getMethod(invoke.getDeclaredTarget().getSelector());
						if (m != null) {
							targetMtd = m;
							break;
						}
					}
			}
		}

		if (targetMtd != null) {
			if (targetMtd.isAbstract()) {
				targetNodes = new HashSet<>(cg.getPossibleTargets(ep, invoke.getCallSite()));
			} else {
				CGNode n = cg.getNode(targetMtd, Everywhere.EVERYWHERE);
				if (n != null)
					targetNodes.add(n);
			}

			if (targetNodes.isEmpty()) {
				try {
					Set<IClass> candidateClass = calculateAbstractORInterfaceTargetClasses(targetMtd, cg);

					if (candidateClass.isEmpty()) {
						CGNode targetNode = ((ExplicitCallGraph) cg).findOrCreateNode(targetMtd, Everywhere.EVERYWHERE);
						targetNodes.add(targetNode);
					} else {
						for (IClass c : candidateClass) {
							for (IMethod m : c.getDeclaredMethods()) {
								CGNode n = ((ExplicitCallGraph) cg).findOrCreateNode(m, Everywhere.EVERYWHERE);
								if (n.getIR() != null && n.getIR().getInstructions() != null) {
									SSAInstruction[] insts = n.getIR().getInstructions();
									for (SSAInstruction tmpInst : insts) {
										if (tmpInst instanceof SSAInvokeInstruction) {
											IMethod tmpTarget = cg.getClassHierarchy().resolveMethod(
													((SSAInvokeInstruction) tmpInst).getDeclaredTarget());
											if (tmpTarget != null) {
												if (!tmpTarget.isAbstract())
													((ExplicitCallGraph) cg).findOrCreateNode(tmpTarget,
															Everywhere.EVERYWHERE);
											}
										}
									}
								}
								if (m.getName().toString().equals(targetMtd.getName().toString())) {
									if (n != null)
										targetNodes.add(n);
								}

							}
						}
					}
				} catch (CancelException e) {
					e.printStackTrace();
				}
			}
		}
		return targetNodes;
	}

	public static Set<IClass> calculateAbstractORInterfaceTargetClasses(IMethod targetMtd, CallGraph cg) {
		Set<IClass> candidateClass = new HashSet<>();
		if (targetMtd.getDeclaringClass().isInterface())
			candidateClass = new HashSet<>(
					cg.getClassHierarchy().getImplementors(targetMtd.getDeclaringClass().getReference()));
		else if (targetMtd.getDeclaringClass().isAbstract())
			candidateClass = new HashSet<>(
					cg.getClassHierarchy().computeSubClasses(targetMtd.getDeclaringClass().getReference()));
		return candidateClass;
	}

	public static void rebuild(SSAPropagationCallGraphBuilder builder, Set<IMethod> abstractEntry) {
		ExplicitCallGraph cg = builder.getCallGraph();

		Queue<ExplicitNode> worklist = new LinkedList<ExplicitNode>();
		cg.getEntrypointNodes().forEach(n -> {
			if (!n.getMethod().isWalaSynthetic())
				worklist.add((ExplicitNode) n);
		});

		/* deal with entry */
		for (IMethod m : abstractEntry) {
			try {
				CGNode node = cg.findOrCreateNode(m, Everywhere.EVERYWHERE);
				worklist.add((ExplicitNode) node);
				cg.registerEntrypoint(node);
				if (m.isAbstract()) {
					Set<IClass> subs = cg.getClassHierarchy().getImplementors(m.getDeclaringClass().getReference());
					if (subs != null) {
						for (IClass sub : subs) {
							IMethod method = sub.getMethod(m.getSelector());
							if (!method.isAbstract()) {
								CGNode subnode = cg.findOrCreateNode(method, Everywhere.EVERYWHERE);
								worklist.add((ExplicitNode) subnode);
								cg.registerEntrypoint(subnode);
							}
						}
					}
				}
			} catch (CancelException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		/* deal with entry can reach */
		HashSet<ExplicitNode> visited = new HashSet<>();
		while (!worklist.isEmpty()) {
			ExplicitNode curr = worklist.remove();
			if (visited.contains(curr))
				continue;
			visited.add(curr);
			if (curr.getIR() == null)
				continue;
			SSAInstruction[] insts = curr.getIR().getInstructions();
			if (insts != null) {
				for (SSAInstruction tmpInst : insts) {
					if (tmpInst instanceof SSAInvokeInstruction) {
						SSAInvokeInstruction invoke = (SSAInvokeInstruction) tmpInst;
						if (invoke.getDeclaredTarget().getSignature().startsWith("java.util.")
								|| invoke.getDeclaredTarget().getSignature().startsWith("java.lang."))
							continue;
						Set<CGNode> tars = cg.getPossibleTargets(curr, invoke.getCallSite());
						if (tars == null || tars.isEmpty()) {
							Set<CGNode> targets = CGHelper.findAllTargets(invoke, curr, cg);
							if (targets != null) {
								for (CGNode target : targets) {
									if (target instanceof ExplicitNode) {
//										if (!cg.hasEdge(curr, target)) {
										((ExplicitNode) curr).addTarget(invoke.getCallSite(), target);
										cg.addEdge(curr, target);
										if (!target.getMethod().getDeclaringClass().getReference().getClassLoader()
												.equals(ClassLoaderReference.Primordial)) {
											worklist.add((ExplicitNode) target);
//												System.out.println("[rebuild cg add] from " + invoke.getCallSite()
//														+ " \n\tto " + target);
										}
//										}
									}
								}
							}
						} else {
							for (CGNode target : tars) {
								if (!worklist.contains(target) && !visited.contains(target))
									if (!target.getMethod().getDeclaringClass().getReference().getClassLoader()
											.equals(ClassLoaderReference.Primordial))
										worklist.add((ExplicitNode) target);
							}
						}
					}
				}
			}
		}
	}

}
