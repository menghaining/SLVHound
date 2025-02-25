package SLVHound.checker.core;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ssa.DefUse;
import com.ibm.wala.ssa.SSAConditionalBranchInstruction;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAInvokeInstruction;
import com.ibm.wala.ssa.analysis.ExplodedControlFlowGraph;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.types.ClassLoaderReference;

import SLVHound.checker.common.cgBuilder.CGHelper;
import SLVHound.checker.core.Util.AuthenticationUtil;
import SLVHound.checker.core.Util.RepoElement;
import SLVHound.checker.core.db.DBHelper;


public class FilterFinder {
	public static boolean usedInCompare(int ret, SSAInstruction inst, DefUse du, HashSet<SSAInstruction> visited) {
		if (visited.contains(inst))
			return false;
		visited.add(inst);
		if (ret > -1) {
			Iterator<SSAInstruction> it = du.getUses(ret);
			while (it.hasNext()) {
				SSAInstruction succInst = it.next();
				if (succInst != null) {
					for (int i = 0; i < succInst.getNumberOfUses(); i++) {
						if (succInst.getUse(i) == ret) {
							if (succInst instanceof SSAConditionalBranchInstruction) {
								return true;
							} else {
								int succDef = succInst.getDef();
								if (usedInCompare(succDef, succInst, du, visited))
									return true;
							}
						}
					}
				}
			}
		}
		return false;
	}
	
	public static void getSingleChecked(CGNode cgNode, HashSet<RepoElement> ret, CallGraph cg) {
		// collect the db get inst, which return value would be also used in compare
		// intra-procedure
		ExplodedControlFlowGraph cfg = ExplodedControlFlowGraph.make(cgNode.getIR());
		Iterator<IExplodedBasicBlock> it = cfg.iterator();
		while (it.hasNext()) {
			IExplodedBasicBlock n = it.next();
			SSAInstruction inst = n.getLastInstruction();
			if (inst instanceof SSAInvokeInstruction) {
				SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;
				// 1. recurse all callees
				HashSet<BasicBlockInContext<IExplodedBasicBlock>> checkedbbs = new HashSet<>();
				if (containsCheckDBHasInvoke(new BasicBlockInContext<IExplodedBasicBlock>(cgNode, n), cg,
						new HashSet<>(), checkedbbs)) {
					// 2. is inst return used in condition check?
					// find all used intra-procedure
					if (usedInCompare(invoke.getDef(), invoke, cgNode.getDU(), new HashSet<SSAInstruction>())) {
						// find!!!
						for (BasicBlockInContext<IExplodedBasicBlock> bb : checkedbbs) {
//							FieldReference auth = AuthenticationUtil.extractGetField(bb);
//							if (auth != null)
//								auths.add(auth);
							RepoElement authRepo = AuthenticationUtil.buildRepoElement(cg, bb);
							if (authRepo != null)
								ret.add(authRepo);
						}

					}

				}
			}
		}

	}
	
	/**
	 * fall into all application callees to check: where contains CheckDBInst
	 * 
	 * @param hashSet
	 */
	public static boolean containsCheckDBHasInvoke(BasicBlockInContext<IExplodedBasicBlock> n, CallGraph cg,
			HashSet<CGNode> visited, HashSet<BasicBlockInContext<IExplodedBasicBlock>> result) {
		// current inst
		SSAInstruction instruction = n.getLastInstruction();
		assert instruction instanceof SSAInvokeInstruction;
		SSAInvokeInstruction invoke = (SSAInvokeInstruction) instruction;
		if (DBHelper.instance().isAction2DBAgentInvoke(n.getNode(), invoke, "get")
				|| DBHelper.instance().isAction2DBAgentInvoke(n.getNode(), invoke, "has")) {
			result.add(n);
			return true;
		}
		// if is application method, fall into callee
		Set<CGNode> callees = CGHelper.findAllTargets(invoke, n.getNode(), cg);
		for (CGNode callee : callees) {
			if (!callee.getMethod().getDeclaringClass().getClassLoader().getReference()
					.equals(ClassLoaderReference.Application))
				return false;
			if (visited.contains(callee))
				return false;
			visited.add(callee);

			if (callee.getIR() == null)
				return false;
			SSAInstruction[] insts = callee.getIR().getInstructions();
			if (insts != null) {
				for (SSAInstruction inst : insts) {
					if (inst instanceof SSAInvokeInstruction) {
						ExplodedControlFlowGraph cfg = ExplodedControlFlowGraph.make(callee.getIR());
						IExplodedBasicBlock callbb = cfg.getBlockForInstruction(inst.iIndex());
						if (containsCheckDBHasInvoke(new BasicBlockInContext<>(callee, callbb), cg, visited, result)) {
							return true;
						}
					}
				}
			}
		}
		return false;
	}
}
