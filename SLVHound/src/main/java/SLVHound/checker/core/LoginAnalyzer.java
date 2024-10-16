package SLVHound.checker.core;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;

import com.ibm.wala.classLoader.BytecodeClass;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.classLoader.ShrikeCTMethod;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.shrikeCT.AnnotationsReader.ElementValue;
import com.ibm.wala.ssa.DefUse;
import com.ibm.wala.ssa.SSACheckCastInstruction;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAInvokeInstruction;
import com.ibm.wala.ssa.SSANewInstruction;
import com.ibm.wala.ssa.SSAReturnInstruction;
import com.ibm.wala.ssa.analysis.ExplodedControlFlowGraph;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.types.FieldReference;
import com.ibm.wala.types.TypeReference;
import com.ibm.wala.types.annotations.Annotation;

import SLVHound.checker.common.cgBuilder.CGHelper;
import SLVHound.checker.core.Util.AuthenticationUtil;
import SLVHound.checker.core.Util.FlowHelper;
import SLVHound.checker.core.Util.RepoElement;
import SLVHound.checker.core.Util.RepoElementUtils;
import SLVHound.checker.core.Util.UserVar;
import SLVHound.checker.core.db.DBHelper;
import SLVHound.checker.core.db.SQLQuery;

public class LoginAnalyzer {

	// Taint Analysis
//	public static HashMap<RepoElement, HashSet<UserVar>> analyzeNormalLogin(HashSet<CGNode> mayLoginMethods,
//			CallGraph cg, PointerAnalysis<InstanceKey> pa, String app) throws IOException {
//
//		TabulationDomain<IDomainElement, BasicBlockInContext<IExplodedBasicBlock>> domain = new TaintDomain<>(
//				DomainElement.ZERO);
//		ITaintPropagationWrapper<IDomainElement> wrapper = new SummaryTaintWrapper(wrapperFile, cg, pa);
//
//		SolverManager<IDomainElement> manager = new SolverManager<>(app, pa, cg, new SourceSinkJSONProvider(), domain,
//				wrapper);
//		/* prepare sources */
//		// 1. param: login parameters
//		// 2. findDB: reachable find DBs from login methods
//		// 3. session: system session creation site
//		manager.getSourceSinkManager().initializeAuthenticationSources(mayLoginMethods, NormalLoginFlowHelper.instance()
//				.collectAuthenticationBBSources(mayLoginMethods, cg, manager.getICFGSupergraph()));
//
//		ITaintSolver solver = new TaintSolver(manager); // sparse
//		solver.runAnalysis();
//		System.out.println("[ifdssovlerdone]");
//		HashMap<RepoElement, HashSet<RepoElement>> answer = NormalLoginFlowHelper.instance()
//				.analyzeResult(((TaintSolver) solver).getTaintFlowResult(), manager);
//
//		/* merge same */
//		HashMap<RepoElement, HashSet<RepoElement>> no_duplicate = new HashMap<>();
//		for (RepoElement key : answer.keySet()) {
//			RepoElement same = RepoElementUtils.contains(no_duplicate.keySet(), key);
//			if (same == null) {
//				no_duplicate.put(key, answer.get(key));
//			} else {
//				no_duplicate.get(same).addAll(answer.get(key));
//			}
//		}
//
//		/* build uservar */
//		HashMap<RepoElement, HashSet<UserVar>> result = new HashMap<>();
//		for (RepoElement key : no_duplicate.keySet()) {
//			HashSet<UserVar> tmp = new HashSet<>();
//			for (RepoElement repo : no_duplicate.get(key)) {
//				UserVar userv = buildUserVar(repo, cg);
//				tmp.add(userv);
//			}
//			if (!tmp.isEmpty())
//				result.put(key, tmp);
//		}
//
//		return result;
//	}

	/** return the user-related key variables */
	public static HashSet<UserVar> analyzeFrameworkLogin(HashSet<CGNode> nodes, CallGraph cg) {
		HashSet<RepoElement> userRepos = new HashSet<>();
		for (CGNode node : nodes) {
			if (!AuthCollecter.mayFrameworkLogin(node.getMethod()))
				continue;

			// Spring security: load user info in configuration method
			if (node.getMethod().getSignature()
					.endsWith("Lorg/springframework/security/core/userdetails/UserDetailsService;")) {
				for (SSAInstruction inst : node.getIR().getInstructions()) {
					if (inst instanceof SSAInvokeInstruction) {
						SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;
						// lambda
						if (invoke.toString().contains("LambdaMetafactory, loadUserByUsername(")) {
							TypeReference type = invoke.getDeclaredTarget().getParameterType(0);
							IClass clazz = cg.getClassHierarchy().lookupClass(type);
							if (clazz != null) {
								Collection<String> sps = ((BytecodeClass<?>) clazz).getAllInterfaceNames();
								boolean flag = false;
								for (String sp : sps) {
									if (DBHelper.instance().isSpringRepositoryClass(sp)) {
										flag = true;
										break;
									}
								}
								if (sps != null && flag) {
									RepoElement ele = new RepoElement(clazz, type, "");
									userRepos.add(ele);
								}
							}
						}
						if (DBHelper.instance().isAction2DBAgentInvoke(node, invoke, "get")) {
							ExplodedControlFlowGraph cfg = ExplodedControlFlowGraph.make(node.getIR());
							IExplodedBasicBlock callbb = cfg.getBlockForInstruction(invoke.iIndex());
							RepoElement re = AuthenticationUtil.buildRepoElement(cg,
									new BasicBlockInContext<IExplodedBasicBlock>(node, callbb));
							userRepos.add(re);
							// collect all fields that used in this ORM object
							// record the field used
							/*
							 * USERobj = queryDBstmt(); 1) USERobj.field; 2) USERobj.getField(); 3)
							 * invoke(USERobj){ USERobj. 1) or 2)}
							 */
							HashSet<FieldReference> frs = new HashSet<>();
							int def = invoke.getDef();
							FlowHelper.findAllGetUses(def, node, cg, frs, new HashSet<CGNode>());
							if (!frs.isEmpty()) {
								re.addORMFields(frs);
							}
						}
					}
				}
				continue;
			}

			// common:
			// from return, split all corresponding instructions
			Set<SSAInstruction> visited = new HashSet<>();
			Queue<SSAInstruction> queue = new LinkedList<>();
			for (SSAInstruction inst : node.getIR().getInstructions()) {
				if (inst instanceof SSAReturnInstruction) {
					SSAReturnInstruction ret = (SSAReturnInstruction) inst;
					if (ret.getResult() != -1) {
						queue.add(inst);
					}
				}
			}
			while (!queue.isEmpty()) {
				SSAInstruction head = queue.remove();
				visited.add(head);

				if (head instanceof SSANewInstruction) {
					Iterator<SSAInstruction> it = node.getDU().getUses(head.getDef());
					while (it.hasNext()) {
						SSAInstruction usedInst = it.next();
						if (usedInst instanceof SSAInvokeInstruction) {
							if (((SSAInvokeInstruction) usedInst).getDeclaredTarget().getName().toString()
									.equals("<init>")) {
								if (!visited.contains(usedInst))
									if (usedInst != null)
										queue.add(usedInst);
							}
						}
					}
				} else {
					if (head instanceof SSAInvokeInstruction) {
						SSAInvokeInstruction invoke = (SSAInvokeInstruction) head;
						boolean add = false;

						HashSet<RepoElement> all_RepoEles = new HashSet<RepoElement>();

						// case 1. this invoke is query db
						if (DBHelper.instance().isAction2DBAgentInvoke(node, invoke, "get")) {
							ExplodedControlFlowGraph cfg = ExplodedControlFlowGraph.make(node.getIR());
							IExplodedBasicBlock callbb = cfg.getBlockForInstruction(invoke.iIndex());
							RepoElement re = AuthenticationUtil.buildRepoElement(cg,
									new BasicBlockInContext<IExplodedBasicBlock>(node, callbb));
							all_RepoEles.add(re);
							add = true;
						}

						// case 2. the callee of this invoke is query db
						// e.g. ret = invoke(arg1, arg2, ...)
						// if target nodes(or callees) contains getDB, add into result
						// dealwith: declare interface, invoke actual
						if (invoke.getDef() > 0) {
							Set<CGNode> targetNodes = CGHelper.findAllTargets(invoke, node, cg);
							for (CGNode targetNode : targetNodes) {
								if (targetNode != null) {
									// find fall into call application callees
									HashSet<CGNode> tmp_visited = new HashSet<>();
									tmp_visited.add(node);
									HashSet<RepoElement> tmp_res = new HashSet<RepoElement>();
									FlowHelper.fromGetDBFallIntoCallees(targetNode, cg, tmp_res, tmp_visited);
									if (tmp_res != null && !tmp_res.isEmpty()) {
										all_RepoEles.addAll(tmp_res);
										add = true;
									}
								}
							}
						}

						if (add) {
							userRepos.addAll(all_RepoEles);
							// collect all fields that used in this ORM object
							// record the field used
							/*
							 * USERobj = queryDBstmt(); 1) USERobj.field; 2) USERobj.getField(); 3)
							 * invoke(USERobj){ USERobj. 1) or 2)}
							 */
							HashSet<FieldReference> frs = new HashSet<>();
							int def = invoke.getDef();
							FlowHelper.findAllGetUses(def, node, cg, frs, new HashSet<CGNode>());
							if (!frs.isEmpty()) {
								for (RepoElement repoEle : all_RepoEles) {
									repoEle.addORMFields(frs);
								}
							}
						}
					}

					// find backward, find all defInst
					// i.e. where this vn from
					for (int i = 0; i < head.getNumberOfUses(); i++) {
						int use = head.getUse(i);
						SSAInstruction defInst = node.getDU().getDef(use);
						if (!visited.contains(defInst))
							if (defInst != null)
								queue.add(defInst);
					}
				}
			}
		}

		// remove duplicate eles
		HashSet<RepoElement> no_duplicate = new HashSet<>();
		for (RepoElement repo : userRepos)
			if (RepoElementUtils.notDuplicated(repo, no_duplicate))
				no_duplicate.add(repo);

		/* build uservar */
		HashSet<UserVar> results = new HashSet<>();
		for (RepoElement repo : no_duplicate) {
			System.out.println("[analyzeFrameworkLogin]" + repo);
			UserVar userv = buildUserVar(repo, cg);
			results.add(userv);
		}

		return results;

	}

	public static UserVar buildUserVar(RepoElement repo, CallGraph cg) {
		UserVar userv = new UserVar(repo);
		// 1. calculate columns of table from DBstmt, contains user and fields
		parseTableColumns(repo, userv, cg);
		// 2. calculate User object and field
		for (FieldReference fr : repo.ORMFields) {
			TypeReference dc = fr.getDeclaringClass();
			if (!userv.getClazz2fields().containsKey(dc))
				userv.getClazz2fields().put(dc, new HashSet<>());
			userv.getClazz2fields().get(dc).add(fr);

		}
		// 3. if use pure sql
		if (repo.originalbb != null) {
			SSAInvokeInstruction inst = (SSAInvokeInstruction) (repo.originalbb.getLastInstruction());
			if (DBHelper.instance().isJdbcTemplateClass(inst.getDeclaredTarget().getSignature())) {
				SQLQuery q = DBHelper.instance().parseSQL(repo.originalbb.getNode(), inst);
				if (q != null) {
					System.out.println("[parsedSQ:]" + q.toString());
					String table = q.getTable();
					List<String> cols = q.getColumnList();
					userv.getTableName2Cloumns().put(table, new HashSet<>(cols));
				}
			}
		}
		return userv;
	}

	private static void parseTableColumns(RepoElement repoEle, UserVar userv, CallGraph cg) {
		if (repoEle.originalbb != null) {
			BasicBlockInContext<IExplodedBasicBlock> bb = repoEle.originalbb;
			SSAInstruction inst = bb.getLastInstruction();
			if (inst instanceof SSAInvokeInstruction) {
				SSAInvokeInstruction inv = (SSAInvokeInstruction) inst;
				// 2.1 ClassType
				TypeReference classType = inv.getDeclaredResultType();
				if (classType.getName().toString().equals("Ljava/lang/Object")) {
					if (bb.getNode() != null) {
						DefUse du = bb.getNode().getDU();
						Iterator<SSAInstruction> uses = du.getUses(inv.getDef());
						while (uses.hasNext()) {
							SSAInstruction useInst = uses.next();
							if (useInst instanceof SSACheckCastInstruction) {
								TypeReference[] resultTypes = ((SSACheckCastInstruction) useInst)
										.getDeclaredResultTypes();
								classType = resultTypes[0];
								break;
							}
						}
					}
				}
				// 2.2 field
				HashSet<String> columns = new HashSet<>();
				// 1) from DB-stmt query statement attributes
				List<String> attrs = DBHelper.instance()
						.parseDBstmt2findAttrs(inv.getDeclaredTarget().getName().toString());
				int maxIndexOfparam = bb.getNode().getMethod().getNumberOfParameters();
				if (!attrs.isEmpty()) {
					int i = 0;
					int shift = 0;
					if (!inv.isStatic()) {
						i = 1;
						shift = 1;
					}

					for (; i < inv.getNumberOfUses(); i++) {
						HashSet<Integer> visited_tmp = new HashSet<>();
						if (!inv.isStatic())
							visited_tmp.add(1);
						int vn = inv.getUse(i);
						if (FlowHelper.isVnFlowFromParam_intra(vn, maxIndexOfparam, bb.getNode().getDU(),
								visited_tmp)) {
							if (i - shift < attrs.size())
								columns.add(attrs.get(i - shift));
						}
					}
				}

				// 1).2 The target parameter type annotation/parameterName represent the
				// operated object fields name
				IMethod callee = cg.getClassHierarchy().resolveMethod(inv.getDeclaredTarget());
				if (callee != null) {
					Collection<Annotation>[] paramannos = ((ShrikeCTMethod) callee).getParameterAnnotations();
					if (paramannos != null) {
						for (Collection<Annotation> param : paramannos) {
							for (Annotation anno : param) {
								if (anno.getType().getName().toString()
										.equals("Lorg/apache/ibatis/annotations/Param")) {
									if (anno.getNamedArguments() != null
											&& anno.getNamedArguments().containsKey("value")) {
										ElementValue v = anno.getNamedArguments().get("value");
										columns.add(v.toString().toLowerCase());
									}
								}
							}
						}
					}
				}

				// 2) ret = findDB, if(ret.field...),
				// then field is concerned
				// e.g. user active status, pwd...
				// TODO:

				// 3) from framework pattern
				if (repoEle.ORMFields != null) {
					for (FieldReference fr : repoEle.ORMFields) {
						if (classType.equals(fr.getDeclaringClass())) {
							columns.add(fr.getName().toString().toLowerCase());
						}
						if (DBHelper.instance()
								.isJavaEEAPIEMClass(((SSAInvokeInstruction) inst).getDeclaredTarget().getSignature())
								|| DBHelper.instance().isMongoDBClass(
										((SSAInvokeInstruction) inst).getDeclaredTarget().getSignature())) {
							columns.add(fr.getName().toString().toLowerCase());
							classType = fr.getDeclaringClass();
						}
					}
				}

				// merge
				if (columns != null && !columns.isEmpty()) {
					if (!userv.getTable2Cloumns().containsKey(classType))
						userv.getTable2Cloumns().put(classType, new HashSet<>());
					userv.getTable2Cloumns().get(classType).addAll(columns);
				}
			}
		}

	}

}
