//package SLVHound.checker.core;
//
//import java.util.Collection;
//import java.util.HashSet;
//import java.util.Iterator;
//import java.util.LinkedList;
//import java.util.Queue;
//import java.util.Set;
//
//import com.ibm.wala.classLoader.BytecodeClass;
//import com.ibm.wala.classLoader.IClass;
//import com.ibm.wala.ipa.callgraph.CGNode;
//import com.ibm.wala.ipa.callgraph.CallGraph;
//import com.ibm.wala.ipa.cfg.BasicBlockInContext;
//import com.ibm.wala.ssa.SSAInstruction;
//import com.ibm.wala.ssa.SSAInvokeInstruction;
//import com.ibm.wala.ssa.SSANewInstruction;
//import com.ibm.wala.ssa.SSAReturnInstruction;
//import com.ibm.wala.ssa.analysis.ExplodedControlFlowGraph;
//import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
//import com.ibm.wala.types.FieldReference;
//import com.ibm.wala.types.TypeReference;
//
//import SLVHound.checker.core.db.DBHelper;
//
//public class LoginFrameworkAnalyzer {
//	/** return the user-related key variables */
//	public static HashSet<UserVar> analyzeFrameworkLogin(CGNode node, CallGraph cg) {
//		HashSet<RepoElement> userRepos = new HashSet<>();
//
//		// Spring security: load user info in configuration method
//		if (node.getMethod().getSignature()
//				.endsWith("Lorg/springframework/security/core/userdetails/UserDetailsService;")) {
//			for (SSAInstruction inst : node.getIR().getInstructions()) {
//				if (inst instanceof SSAInvokeInstruction) {
//					SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;
//					// lambda
//					if (invoke.toString().contains("LambdaMetafactory, loadUserByUsername(")) {
//						TypeReference type = invoke.getDeclaredTarget().getParameterType(0);
//						IClass clazz = cg.getClassHierarchy().lookupClass(type);
//						if (clazz != null) {
//							Collection<String> sps = ((BytecodeClass<?>) clazz).getAllInterfaceNames();
//							boolean flag = false;
//							for (String sp : sps) {
//								if (DBHelper.instance().isSpringRepositoryClass(sp)) {
//									flag = true;
//									break;
//								}
//							}
//							if (sps != null && flag) {
//								RepoElement ele = new RepoElement(clazz, type, "");
//								userRepos.add(ele);
//							}
//						}
//					}
//					if (DBHelper.instance().isAction2DBAgentInvoke(node, invoke, "get")) {
//						ExplodedControlFlowGraph cfg = ExplodedControlFlowGraph.make(node.getIR());
//						IExplodedBasicBlock callbb = cfg.getBlockForInstruction(invoke.iIndex());
//						RepoElement re = AuthenticationUtil.buildRepoElement(cg,
//								new BasicBlockInContext<IExplodedBasicBlock>(node, callbb));
//						userRepos.add(re);
//						// collect all fields that used in this ORM object
//						// record the field used
//						/*
//						 * USERobj = queryDBstmt(); 1) USERobj.field; 2) USERobj.getField(); 3)
//						 * invoke(USERobj){ USERobj. 1) or 2)}
//						 */
//						HashSet<FieldReference> frs = new HashSet<>();
//						int def = invoke.getDef();
//						FlowHelper.findAllGetUses(def, node, cg, frs, new HashSet<CGNode>());
//						if (!frs.isEmpty()) {
//							re.addORMFields(frs);
//						}
//					}
//				}
//			}
//			continue;
//		}
//
//		// common:
//		// from return, split all corresponding instructions
//		Set<SSAInstruction> visited = new HashSet<>();
//		Queue<SSAInstruction> queue = new LinkedList<>();
//		for (SSAInstruction inst : node.getIR().getInstructions()) {
//			if (inst instanceof SSAReturnInstruction) {
//				SSAReturnInstruction ret = (SSAReturnInstruction) inst;
//				if (ret.getResult() != -1) {
//					queue.add(inst);
//				}
//			}
//		}
//		while (!queue.isEmpty()) {
//			SSAInstruction head = queue.remove();
//			visited.add(head);
//
//			if (head instanceof SSANewInstruction) {
//				Iterator<SSAInstruction> it = node.getDU().getUses(head.getDef());
//				while (it.hasNext()) {
//					SSAInstruction usedInst = it.next();
//					if (usedInst instanceof SSAInvokeInstruction) {
//						if (((SSAInvokeInstruction) usedInst).getDeclaredTarget().getName().toString()
//								.equals("<init>")) {
//							if (!visited.contains(usedInst))
//								if (usedInst != null)
//									queue.add(usedInst);
//						}
//					}
//				}
//			} else {
//				if (head instanceof SSAInvokeInstruction) {
//					SSAInvokeInstruction invoke = (SSAInvokeInstruction) head;
//					boolean add = false;
//
//					HashSet<RepoElement> all_RepoEles = new HashSet<RepoElement>();
//
//					// case 1. this invoke is query db
//					if (DBHelper.instance().isAction2DBAgentInvoke(node, invoke, "get")) {
//						ExplodedControlFlowGraph cfg = ExplodedControlFlowGraph.make(node.getIR());
//						IExplodedBasicBlock callbb = cfg.getBlockForInstruction(invoke.iIndex());
//						RepoElement re = AuthenticationUtil.buildRepoElement(cg,
//								new BasicBlockInContext<IExplodedBasicBlock>(node, callbb));
//						all_RepoEles.add(re);
//						add = true;
//					}
//
//					// case 2. the callee of this invoke is query db
//					// e.g. ret = invoke(arg1, arg2, ...)
//					// if target nodes(or callees) contains getDB, add into result
//					// dealwith: declare interface, invoke actual
//					if (invoke.getDef() > 0) {
//						Set<CGNode> targetNodes = CGHelper.findAllTargets(invoke, node, cg);
//						for (CGNode targetNode : targetNodes) {
//							if (targetNode != null) {
//								// find fall into call application callees
//								HashSet<CGNode> tmp_visited = new HashSet<>();
//								tmp_visited.add(node);
//								HashSet<RepoElement> tmp_res = new HashSet<RepoElement>();
//								FlowHelper.fromGetDBFallIntoCallees(targetNode, cg, tmp_res, tmp_visited);
//								if (tmp_res != null && !tmp_res.isEmpty()) {
//									all_RepoEles.addAll(tmp_res);
//									add = true;
//								}
//							}
//						}
//					}
//
//					if (add) {
//						userRepos.addAll(all_RepoEles);
//						// collect all fields that used in this ORM object
//						// record the field used
//						/*
//						 * USERobj = queryDBstmt(); 1) USERobj.field; 2) USERobj.getField(); 3)
//						 * invoke(USERobj){ USERobj. 1) or 2)}
//						 */
//						HashSet<FieldReference> frs = new HashSet<>();
//						int def = invoke.getDef();
//						FlowHelper.findAllGetUses(def, node, cg, frs, new HashSet<CGNode>());
//						if (!frs.isEmpty()) {
//							for (RepoElement repoEle : all_RepoEles) {
//								repoEle.addORMFields(frs);
//							}
//						}
//					}
//				}
//
//				// find backward, find all defInst
//				// i.e. where this vn from
//				for (int i = 0; i < head.getNumberOfUses(); i++) {
//					int use = head.getUse(i);
//					SSAInstruction defInst = node.getDU().getDef(use);
//					if (!visited.contains(defInst))
//						if (defInst != null)
//							queue.add(defInst);
//				}
//			}
//		}
//
//		// remove duplicate eles
//		HashSet<RepoElement> no_duplicate = new HashSet<>();
//		for (RepoElement repo : userRepos)
//			if (RepoElementUtils.notDuplicated(repo, no_duplicate))
//				no_duplicate.add(repo);
//
//		/* build uservar */
//		HashSet<UserVar> results = new HashSet<>();
//		for (RepoElement repo : no_duplicate) {
//			System.out.println("[analyzeFrameworkLogin]" + repo);
//			UserVar userv = buildUserVar(repo, cg);
//			results.add(userv);
//		}
//
//		return results;
//
//	}
//
//}
