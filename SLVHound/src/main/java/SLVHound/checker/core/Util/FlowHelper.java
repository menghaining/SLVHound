package SLVHound.checker.core.Util;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Set;
import java.util.Map.Entry;

import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ssa.DefUse;
import com.ibm.wala.ssa.SSAArrayStoreInstruction;
import com.ibm.wala.ssa.SSACheckCastInstruction;
import com.ibm.wala.ssa.SSAConditionalBranchInstruction;
import com.ibm.wala.ssa.SSAGetInstruction;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAInvokeInstruction;
import com.ibm.wala.ssa.SSANewInstruction;
import com.ibm.wala.ssa.SSAReturnInstruction;
import com.ibm.wala.ssa.analysis.ExplodedControlFlowGraph;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.types.FieldReference;
import com.ibm.wala.types.TypeReference;

import SLVHound.checker.common.cgBuilder.CGHelper;
import SLVHound.checker.core.db.DBHelper;

public class FlowHelper {
	/**
	 * find in all callees layer by layer;</br>
	 * find all queryDB stmts, which flow into the return value of given node
	 */
	public static boolean fromGetDBFallIntoCallees(CGNode node, CallGraph cg, HashSet<RepoElement> results,
			HashSet<CGNode> visited) {
		boolean find = false;

		if (visited.contains(node))
			return find;
		visited.add(node);

		if (node.getIR() == null)
			return find;

		Set<SSAInstruction> handledInsts = new HashSet<>();
		Queue<SSAInstruction> queue = new LinkedList<>();

		for (SSAInstruction inst : node.getIR().getInstructions()) {
			if (inst instanceof SSAReturnInstruction) {
				SSAReturnInstruction ret = (SSAReturnInstruction) inst;
				if (ret.getResult() != -1) {
					queue.add(inst);
				}
			}
		}

		Queue<SSAInvokeInstruction> invokes = new LinkedList<>();
		HashMap<RepoElement, SSAInvokeInstruction> repo2defInvoke = new HashMap<>();

		// search all queryDB intra-procedural
		while (!queue.isEmpty()) {
			SSAInstruction head = queue.remove();
			handledInsts.add(head);

			if (head instanceof SSANewInstruction) {
				Iterator<SSAInstruction> it = node.getDU().getUses(head.getDef());
				while (it.hasNext()) {
					SSAInstruction usedInst = it.next();
					if (usedInst instanceof SSAInvokeInstruction) {
						if (((SSAInvokeInstruction) usedInst).getDeclaredTarget().getName().toString()
								.equals("<init>")) {
							if (!handledInsts.contains(usedInst))
								if (usedInst != null)
									queue.add(usedInst);
						}
					}
				}
			} else {
				if (head instanceof SSAInvokeInstruction) {
					SSAInvokeInstruction invoke = (SSAInvokeInstruction) head;
					// find the get db instruction
					if (DBHelper.instance().isAction2DBAgentInvoke(node, invoke, "get")
							|| DBHelper.instance().isJavaEEAction(node, invoke, "get", visited)
							|| DBHelper.instance().isJdbcTemplate(node, invoke, "get")) {
						ExplodedControlFlowGraph cfg = ExplodedControlFlowGraph.make(node.getIR());
						IExplodedBasicBlock callbb = cfg.getBlockForInstruction(invoke.iIndex());
						RepoElement re = AuthenticationUtil.buildRepoElement(cg,
								new BasicBlockInContext<IExplodedBasicBlock>(node, callbb));
						if (re != null) {
							results.add(re);
							find = true;
							repo2defInvoke.put(re, invoke);
						}

					} else {
						// inter-procedure deal later
						invokes.add(invoke);
					}

				}
				// find where all used params in this inst from
				// find backward, find all defInst
				for (int i = 0; i < head.getNumberOfUses(); i++) {
					int use = head.getUse(i);
					SSAInstruction defInst = node.getDU().getDef(use);
					if (!handledInsts.contains(defInst))
						if (defInst != null)
							queue.add(defInst);
				}
			}

		}

		// search all callees
//		if (results.isEmpty()) {
		for (SSAInvokeInstruction invoke : invokes) {
			// if not: fall into it iff application method invoke
			Set<CGNode> targetNodes = CGHelper.findAllTargets(invoke, node, cg);
			for (CGNode targetNode : targetNodes) {
				if (targetNode != null && !targetNode.getMethod().getDeclaringClass().getClassLoader().getReference()
						.equals(ClassLoaderReference.Primordial)) {
					// find fall into call application callees
					if (fromGetDBFallIntoCallees(targetNode, cg, results, visited)) {
						find = true;
						for (RepoElement key : results) {
							repo2defInvoke.put(key, invoke);
						}
					}
				}
			}
		}
//		}

		// add fields
		for (Entry<RepoElement, SSAInvokeInstruction> pair : repo2defInvoke.entrySet()) {
			// collect all fields that used in this ORM object
			// record the field used
			/*
			 * ORMobj = queryDBstmt(); 1) ORMobj.field; 2) ORMobj.getField(); 3)
			 * invoke(ORMobj){ ORMobj. 1) or 2)}
			 */
			SSAInvokeInstruction invoke = pair.getValue();
			HashSet<FieldReference> frs = new HashSet<>();
			int def = invoke.getDef();
			FlowHelper.findAllGetUses(def, node, cg, frs, new HashSet<CGNode>());
			if (!frs.isEmpty()) {
				RepoElement repoEle = pair.getKey();
				repoEle.addORMFields(frs);
			}
		}

		visited.remove(node);
		return find;
	}

	/**
	 * Intra-procedural.</br>
	 * calculate all instructions that the return vars of instructions set A would
	 * flow to given signature B
	 * 
	 * @param node
	 * @param cg
	 */
	public static HashSet<SSAInstruction> fromA2B(HashSet<SSAInstruction> a, String sig, CGNode node, CallGraph cg) {
		HashSet<SSAInstruction> jwts = new HashSet<>();

		DefUse du = node.getDU();

		HashSet<SSAInstruction> visited = new HashSet<>();
		Queue<SSAInstruction> queue = new LinkedList<>();
		for (SSAInstruction invoke : a)
			queue.add(invoke);

		while (!queue.isEmpty()) {
			SSAInstruction head = queue.remove();
			visited.add(head);

			if (head instanceof SSAInvokeInstruction) {
				SSAInvokeInstruction inv = (SSAInvokeInstruction) head;
				// is init mtd
				if (inv.getDeclaredTarget().getName().toString().equals("<init>")) {
					// find all uses
					Iterator<SSAInstruction> uses = du.getUses(inv.getUse(0));
					while (uses.hasNext()) {
						SSAInstruction use = uses.next();
						if (!visited.contains(use))
							queue.add(use);
					}
				} else {
					// this level
					if (inv.getDeclaredTarget().getSignature().startsWith(sig)) {
						jwts.add(inv);
					} else {
						// fall into callees, find
						Set<CGNode> targets = CGHelper.findAllTargets(inv, node, cg);
						for (CGNode target : targets) {
							if (target != null) {
								// check each invoke instruction
								for (SSAInstruction inst : target.getIR().getInstructions()) {
									if (inst instanceof SSAInvokeInstruction) {
										SSAInvokeInstruction targetInvoke = (SSAInvokeInstruction) inst;
										if (targetInvoke.getDeclaredTarget().getSignature().contains(sig)) {
											jwts.add(inv);
											break;
										}
									}
								}

							}
						}
					}
				}
			}

			if (head instanceof SSAArrayStoreInstruction) {
				SSAArrayStoreInstruction store = (SSAArrayStoreInstruction) head;
				// find all uses
				Iterator<SSAInstruction> uses = du.getUses(store.getArrayRef());
				while (uses.hasNext()) {
					SSAInstruction use = uses.next();
					if (!visited.contains(use))
						queue.add(use);
				}
			}

			if (head.getDef() != -1) {
				Iterator<SSAInstruction> uses = du.getUses(head.getDef());
				while (uses.hasNext()) {
					SSAInstruction use = uses.next();
					if (!visited.contains(use))
						queue.add(use);
				}
			}
		}
		return jwts;
	}

	/**
	 * Find All Fields of vn that used in node and its callee nodes, calculate layer
	 * by layer.</br>
	 * </br>
	 * Analyze inter-procedure.</br>
	 * </br>
	 * USERobj = queryDBstmt(); 1) USERobj.field; 2) USERobj.getField(); 3)
	 * invoke(USERobj){ USERobj. 1) or 2)}
	 */
	public static void findAllGetUses(int vn, CGNode node, CallGraph cg, HashSet<FieldReference> ret,
			HashSet<CGNode> visited) {
		if (visited.contains(node))
			return;
		visited.add(node);

		if (node.getMethod().getDeclaringClass().getClassLoader().getReference()
				.equals(ClassLoaderReference.Primordial))
			return;

		if (node.getIR() == null || node.getDU() == null)
			return;

		Iterator<SSAInstruction> it = node.getDU().getUses(vn);
		while (it.hasNext()) {
			SSAInstruction i = it.next();
			// 1. vn.field
			if (i instanceof SSAGetInstruction && i.getUse(0) == vn) {
				SSAGetInstruction getInst = (SSAGetInstruction) i;
				FieldReference f = getInst.getDeclaredField();
				ret.add(f);
				int def = getInst.getDef();
				visited.remove(node);
				findAllGetUses(def, node, cg, ret, visited);
			}
			if (i instanceof SSAInvokeInstruction) {
				SSAInvokeInstruction invoke = (SSAInvokeInstruction) i;
				// 2. vn.foo() and m.foo(vn)
				int actualVn = -1;
				for (int j = 0; j < invoke.getNumberOfUses(); j++) {
					if (invoke.getUse(j) == vn) {
						actualVn = j + 1;
					}
				}

				if (actualVn == -1)
					continue;

				Set<CGNode> targets = CGHelper.findAllTargets(invoke, node, cg);
				for (CGNode tar : targets) {
					findAllGetUses(actualVn, tar, cg, ret, visited);
				}
			}

			if (i instanceof SSACheckCastInstruction && i.getUse(0) == vn) {
				int casted = i.getDef();
				visited.remove(node);
				findAllGetUses(casted, node, cg, ret, visited);
			}

		}
	}

	/**
	 * Is the variable vn defined from method parameters?</br>
	 * Analyze intra-procedure.</br>
	 * </br>
	 * visited need to contain '1' iff current node is not static
	 */
	public static boolean isVnFlowFromParam_intra(int vn, int maxIndexOfparam, DefUse du, HashSet<Integer> visited) {
		if (visited.contains(vn))
			return false;
		visited.add(vn);

		if (vn <= maxIndexOfparam)
			return true;

		SSAInstruction defInst = du.getDef(vn);
		if (defInst != null) {
			if (defInst instanceof SSANewInstruction) {
				Iterator<SSAInstruction> it = du.getUses(defInst.getDef());
				while (it.hasNext()) {
					SSAInstruction usedInst = it.next();
					if (usedInst instanceof SSAInvokeInstruction) {
						if (((SSAInvokeInstruction) usedInst).getDeclaredTarget().getName().toString().equals("<init>")
								&& usedInst.getUse(0) == defInst.getDef()) {
							for (int i = 1; i < usedInst.getNumberOfUses(); i++) {
								int use = usedInst.getUse(i);
								if (isVnFlowFromParam_intra(use, maxIndexOfparam, du, visited))
									return true;
							}
						}
					}
				}
			} else {
				for (int i = 0; i < defInst.getNumberOfUses(); i++) {
					int use = defInst.getUse(i);
					if (isVnFlowFromParam_intra(use, maxIndexOfparam, du, visited))
						return true;
				}
			}
		}

		return false;
	}

	/**
	 * Is variable useVn defined from the DB-invoke Instruction?</br>
	 * </br>
	 * 
	 * Analyze intra-procedure.</br>
	 */
	public static boolean isFromFindDB(int useVn, CGNode cgNode, TypeReference infoRepoRef, CallGraph cg,
			HashSet<SSAInstruction> visited) {
		DefUse du = cgNode.getDU();
		SSAInstruction defInst = du.getDef(useVn);
		if (defInst == null)
			return false;
		if (visited.contains(defInst))
			return false;
		visited.add(defInst);

		if (defInst instanceof SSAInvokeInstruction) {
			SSAInvokeInstruction defInvoke = (SSAInvokeInstruction) defInst;
			TypeReference typeRef = defInvoke.getDeclaredTarget().getDeclaringClass();
			if (AuthenticationUtil.canAssignableFrom(typeRef, infoRepoRef, cgNode.getClassHierarchy())) {
				if (DBHelper.instance().isAction2DBAgentInvoke(cgNode, defInvoke, "get")) {
					return true;
				}
			}

			// TODO: deal with intra-procedure
		}

		for (int i = 0; i < defInst.getNumberOfUses(); i++) {
			if (isFromFindDB(defInst.getUse(i), cgNode, infoRepoRef, cg, visited))
				return true;
		}
		return false;
	}

	public static void flow2Check_calAll_intra(int ret, SSAInstruction inst, DefUse du,
			HashSet<SSAConditionalBranchInstruction> result, HashSet<SSAInstruction> visited) {
		if (visited.contains(inst))
			return;
		visited.add(inst);
		if (ret > -1) {
			Iterator<SSAInstruction> it = du.getUses(ret);
			while (it.hasNext()) {
				SSAInstruction usedInst = it.next();
				if (usedInst != null) {
					for (int i = 0; i < usedInst.getNumberOfUses(); i++) {
						if (usedInst.getUse(i) == ret) {
							if (usedInst instanceof SSAConditionalBranchInstruction) {
								result.add((SSAConditionalBranchInstruction) usedInst);
							} else {
								int succDef = usedInst.getDef();
								flow2Check_calAll_intra(succDef, usedInst, du, result, visited);
							}
						}
					}
				}
			}
		}
	}

	public static boolean hasArgFlowFromParam_intra(SSAInstruction inst, int maxIndexOfparam, boolean mtdIsStatic,
			DefUse du, HashSet<Integer> visisted) {
		for (int i = 0; i < inst.getNumberOfUses(); i++) {
			if (i == 0)
				if (inst instanceof SSAInvokeInstruction) {
					if (((SSAInvokeInstruction) inst).getDeclaredTarget().getName().toString().equals("<init>"))
						continue;
				}

			int use = inst.getUse(i);
			if (use <= maxIndexOfparam) {
				if (!mtdIsStatic) {
					if (use != 1)// not #this
						return true;
				} else
					return true;
			}

			SSAInstruction def = du.getDef(use);
			if (visisted.contains(use))
				return false;
			visisted.add(use);

			if (def != null) {
				if (def instanceof SSANewInstruction) {
					Iterator<SSAInstruction> it = du.getUses(def.getDef());
					while (it.hasNext()) {
						SSAInstruction usedInst = it.next();
						if (usedInst instanceof SSAInvokeInstruction) {
							if (((SSAInvokeInstruction) usedInst).getDeclaredTarget().getName().toString()
									.equals("<init>") && usedInst.getUse(0) == def.getDef()) {
								boolean ret = hasArgFlowFromParam_intra(usedInst, maxIndexOfparam, mtdIsStatic, du,
										visisted);
								if (ret)
									return true;
							}
						}
					}
				} else {
					boolean ret = hasArgFlowFromParam_intra(def, maxIndexOfparam, mtdIsStatic, du, visisted);
					if (ret)
						return true;
				}
			}
		}
		return false;
	}

}
