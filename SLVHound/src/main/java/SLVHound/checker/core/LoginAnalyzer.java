package SLVHound.checker.core;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.Map.Entry;

import com.ibm.wala.classLoader.BytecodeClass;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.classLoader.ShrikeCTMethod;
import com.ibm.wala.dataflow.IFDS.ISupergraph;
import com.ibm.wala.dataflow.IFDS.TabulationDomain;
import com.ibm.wala.dataflow.IFDS.TabulationResult;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.shrikeCT.AnnotationsReader.ElementValue;
import com.ibm.wala.ssa.DefUse;
import com.ibm.wala.ssa.IR;
import com.ibm.wala.ssa.SSACheckCastInstruction;
import com.ibm.wala.ssa.SSAConditionalBranchInstruction;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAInvokeInstruction;
import com.ibm.wala.ssa.SSANewInstruction;
import com.ibm.wala.ssa.SSAReturnInstruction;
import com.ibm.wala.ssa.analysis.ExplodedControlFlowGraph;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.types.FieldReference;
import com.ibm.wala.types.TypeReference;
import com.ibm.wala.types.annotations.Annotation;
import com.ibm.wala.util.collections.Pair;
import com.ibm.wala.util.intset.IntIterator;
import com.ibm.wala.util.intset.IntSet;
import com.ibm.wala.util.intset.MutableSparseIntSet;

import SLVHound.checker.common.cgBuilder.CGHelper;
import SLVHound.checker.core.Util.AuthenticationUtil;
import SLVHound.checker.core.Util.FlowHelper;
import SLVHound.checker.core.Util.RepoElement;
import SLVHound.checker.core.Util.RepoElementUtils;
import SLVHound.checker.core.Util.UserVar;
import SLVHound.checker.core.db.DBHelper;
import SLVHound.checker.core.db.SQLQuery;
import SLVHound.checker.core.infer.TaintSolver;
import SLVHound.checker.core.infer.dataflow.AccessPath;
import SLVHound.checker.core.infer.dataflow.SourceContext;
import SLVHound.checker.core.infer.dataflow.TaintDomainElement;
import SLVHound.checker.core.infer.dataflow.TaintManager;
import SLVHound.checker.core.infer.dataflow.TaintProblem;

public class LoginAnalyzer {
	public static HashMap<RepoElement, HashSet<UserVar>> analyze(HashSet<CGNode> loginMtds, HashSet<CGNode> filterNodes,
			CallGraph cg, String app) {
		HashMap<RepoElement, HashSet<UserVar>> result = new HashMap<>();
		HashSet<CGNode> nodes = new HashSet<>();
		nodes.addAll(loginMtds);
		nodes.addAll(filterNodes);
		
		TaintManager manager = new TaintManager(cg, nodes);
		TaintSolver solver = new TaintSolver(new TaintProblem(manager));
		solver.run();
		result.putAll(resultAnalyze(solver.getResult(), manager));
		result.put(RepoElement.frmkEle, analyzeFrameworkLogin(nodes, cg));
		return result;

	}

	private static HashMap<RepoElement, HashSet<UserVar>> resultAnalyze(
			TabulationResult<BasicBlockInContext<IExplodedBasicBlock>, CGNode, TaintDomainElement> result,
			TaintManager manager) {
		HashMap<RepoElement, HashSet<RepoElement>> authStatusRepo2infoRepo = new HashMap<>();

		ISupergraph<BasicBlockInContext<IExplodedBasicBlock>, CGNode> icfgs = manager.getIsg();

		/* 1. collect all DB operation instructions and its corresponding facts */
		Map<BasicBlockInContext<IExplodedBasicBlock>, IntSet> findDBs = new HashMap<>();
		Map<BasicBlockInContext<IExplodedBasicBlock>, IntSet> saveDBs = new HashMap<>();
		for (BasicBlockInContext<IExplodedBasicBlock> bb : icfgs) {
			SSAInstruction inst = bb.getDelegate().getInstruction();
			if (inst == null)
				continue;
			IR ir = bb.getNode().getIR();
			if (ir == null)
				continue;

			if (!(inst instanceof SSAInvokeInstruction))
				continue;
			SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;

			/* 1.1 collect the invokes which find dbs */
			if (DBHelper.instance().isAction2DBAgentInvoke(bb.getNode(), invoke, "get")) {
				if (result.getResult(bb).size() > 1) {
					IntSet fs = filterUsedDBFacts(invoke, result.getResult(bb), manager.getDomain());
					if (fs.size() > 0)
						findDBs.put(bb, fs);
				}
			}
			/* 1.2 collect the invokes which save dbs */
			if (DBHelper.instance().isAction2DBAgentInvoke(bb.getNode(), invoke, "save")) {
				if (result.getResult(bb).size() > 1) {
					IntSet fs = filterUsedFacts(invoke, result.getResult(bb), manager.getDomain());
					if (fs.size() > 0) {
						saveDBs.put(bb, fs);
					}
				}
			}

		}

		/* 2. handle save DBs */
		for (BasicBlockInContext<IExplodedBasicBlock> savebb : saveDBs.keySet()) {
			IntSet facts = saveDBs.get(savebb);
			HashMap<String, MutableSparseIntSet> type2facts = new HashMap<>();
			SSAInstruction invoke = savebb.getLastInstruction();
			splitFactSrcs(invoke, manager.getDomain(), facts, type2facts);

			if (type2facts.get("param") != null && type2facts.get("param").size() > 0) {
				if (type2facts.get("findDB") != null && type2facts.get("findDB").size() > 0) {
					HashMap<BasicBlockInContext<IExplodedBasicBlock>, HashSet<SourceContext>> finddb2src = new HashMap<>();
					boolean fromparam = false;
					IntIterator it = type2facts.get("findDB").intIterator();
					while (it.hasNext()) {
						int f = it.next();
						BasicBlockInContext<IExplodedBasicBlock> srcbb = manager.getDomain().getMappedObject(f)
								.getSource().getBlock();
						IntSet srcFacts = result.getResult(srcbb);
						HashMap<String, MutableSparseIntSet> type2facts_src = new HashMap<>();
						splitFactSrcs(srcbb.getLastInstruction(), manager.getDomain(), srcFacts, type2facts_src);
						if (type2facts_src.get("param") != null && type2facts_src.get("param").size() > 0) {
							if (type2facts_src.get("findDB") != null && type2facts_src.get("findDB").size() > 0) {
								continue;
							}
							// is the fist findDB?
							if (notFirstFindDB(manager.getDomain(), manager.getIsg(), srcbb, result))
								continue;

							// findDB using out-suppiled parameter?
							if (!finddb2src.containsKey(srcbb))
								finddb2src.put(srcbb, new HashSet<>());
							type2facts_src.get("param").foreach(x -> {
								finddb2src.get(srcbb).add(manager.getDomain().getMappedObject(x).getSource());
							});

							fromparam = true;
						}
					}
					if (!fromparam)
						continue;

					// 1. from sessionid
					if (type2facts.get("session") != null && type2facts.get("session").size() > 0) {
						RepoElement authRepo = AuthenticationUtil.buildRepoElement(manager.getCallgraph(), savebb);
						if (authRepo == null) {
							System.err.println("[authRepo][cannot find field] " + savebb);
							continue;
						}

						finddb2src.keySet().forEach(key -> {
							// findDB used in condition pare inst
							if (FilterFinder.usedInCompare(key.getLastInstruction().getDef(), key.getLastInstruction(),
									key.getNode().getDU(), new HashSet<SSAInstruction>())) {
								RepoElement infoRepo = AuthenticationUtil.buildRepoElement(manager.getCallgraph(), key);

								if (infoRepo == null) {
									System.err.println("[infoRepo][cannot find field] " + key);
								} else {
									// TODO: param flow with session ID from same path
//									flowTogether(savebb, finddb2src.get(key), icfgs, result, manager.getDomain(),
//											new HashSet<BasicBlockInContext<IExplodedBasicBlock>>());

									if (!authStatusRepo2infoRepo.containsKey(authRepo))
										authStatusRepo2infoRepo.put(authRepo, new HashSet<>());
									authStatusRepo2infoRepo.get(authRepo).add(infoRepo);
								}
							}
						});
					} else {
						// 2. write to response
						SSAInvokeInstruction inst = (SSAInvokeInstruction) savebb.getLastInstruction();
						for (int i = 1; i < inst.getNumberOfUses(); i++) {
							int vn = inst.getUse(i);
							Map<IExplodedBasicBlock, Set<Pair<Integer, Boolean>>> writeRes_visited = new HashMap<>();
							boolean written = isWrite2Response(savebb, vn, icfgs, writeRes_visited);
							if (written) {
								RepoElement authRepo = AuthenticationUtil.buildRepoElement(manager.getCallgraph(),
										savebb);
								if (authRepo == null) {
									System.err.println("[authRepo][cannot find field] " + savebb);
									continue;
								}
								finddb2src.keySet().forEach(key -> {
									// findDB used in condition pare inst
									RepoElement infoRepo = AuthenticationUtil.buildRepoElement(manager.getCallgraph(),
											key);
									if (infoRepo == null) {
										System.err.println("[infoRepo][cannot find field] " + savebb);
									} else {
										if (!authStatusRepo2infoRepo.containsKey(authRepo))
											authStatusRepo2infoRepo.put(authRepo, new HashSet<>());
										authStatusRepo2infoRepo.get(authRepo).add(infoRepo);
									}
								});
							}
						}
					}
				}
			}
		}

		/* merge same */
		HashMap<RepoElement, HashSet<RepoElement>> no_duplicate = new HashMap<>();
		for (RepoElement key : authStatusRepo2infoRepo.keySet()) {
			RepoElement same = RepoElementUtils.contains(no_duplicate.keySet(), key);
			if (same == null) {
				no_duplicate.put(key, authStatusRepo2infoRepo.get(key));
			} else {
				no_duplicate.get(same).addAll(authStatusRepo2infoRepo.get(key));
			}
		}

		/* build uservar */
		HashMap<RepoElement, HashSet<UserVar>> res = new HashMap<>();
		for (RepoElement key : no_duplicate.keySet()) {
			HashSet<UserVar> tmp = new HashSet<>();
			for (RepoElement repo : no_duplicate.get(key)) {
				UserVar userv = buildUserVar(repo, manager.getCallgraph());
				tmp.add(userv);
			}
			if (!tmp.isEmpty())
				res.put(key, tmp);
		}
		return res;
	}

	/** return the user-related key variables */
	private static HashSet<UserVar> analyzeFrameworkLogin(HashSet<CGNode> nodes, CallGraph cg) {
		HashSet<RepoElement> userRepos = new HashSet<>();
		for (CGNode node : nodes) {
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

	private static IntSet filterUsedDBFacts(SSAInvokeInstruction invoke, IntSet result,
			TabulationDomain<TaintDomainElement, BasicBlockInContext<IExplodedBasicBlock>> domain) {
		IntSet facts = filterUsedFacts(invoke, result, domain);
		MutableSparseIntSet ret = MutableSparseIntSet.makeEmpty();
		facts.foreach(x -> {
			if (x == 0)
				return;
			TaintDomainElement de = domain.getMappedObject(x);
			if (de.getSource().getType().equals("param"))
				ret.add(x);
		});
		return ret;
	}

	private static IntSet filterUsedFacts(SSAInstruction inst, IntSet result,
			TabulationDomain<TaintDomainElement, BasicBlockInContext<IExplodedBasicBlock>> domain) {
		MutableSparseIntSet facts = MutableSparseIntSet.makeEmpty();
		result.foreach(x -> {
			if (x == 0)
				return;
			TaintDomainElement de = domain.getMappedObject(x);
			AccessPath ap = de.getAccessPath();
			int vn = ap.getBase();
			for (int i = 0; i < inst.getNumberOfUses(); i++) {
				if (inst.getUse(i) == vn) {
					facts.add(x);
				}
			}
		});
		return facts;
	}

	private static HashMap<BasicBlockInContext<IExplodedBasicBlock>, Boolean> visited_firstDB = new HashMap<>();

	private static boolean notFirstFindDB(
			TabulationDomain<TaintDomainElement, BasicBlockInContext<IExplodedBasicBlock>> domain,
			ISupergraph<BasicBlockInContext<IExplodedBasicBlock>, CGNode> icfgSupergraph,
			BasicBlockInContext<IExplodedBasicBlock> bb,
			TabulationResult<BasicBlockInContext<IExplodedBasicBlock>, CGNode, TaintDomainElement> result) {
		if (visited_firstDB.containsKey(bb))
			return visited_firstDB.get(bb);

		IntSet facts = result.getResult(bb);
		IntIterator factsit = facts.intIterator();
		boolean findDB = false;
		boolean param = false;
		while (factsit.hasNext()) {
			int x = factsit.next();
			if (x == 0)
				continue;
			TaintDomainElement de = domain.getMappedObject(x);
			if (de.getSource().getType().equals("findDB"))
				findDB = true;
			if (de.getSource().getType().equals("param"))
				param = true;
		}
		visited_firstDB.put(bb, false);
		if (param) {
			if (findDB) {
				visited_firstDB.put(bb, true);
				return true;
			}
			for (BasicBlockInContext<IExplodedBasicBlock> entry : icfgSupergraph.getEntriesForProcedure(bb.getNode())) {
				Iterator<BasicBlockInContext<IExplodedBasicBlock>> it = icfgSupergraph.getPredNodes(entry);
				while (it.hasNext()) {
					BasicBlockInContext<IExplodedBasicBlock> cs = it.next();
					boolean status = notFirstFindDB(domain, icfgSupergraph, cs, result);
					if (status) {
						visited_firstDB.put(bb, true);
						return true;
					}
				}
			}
		}
		return false;
	}

	private static void splitFactSrcs(SSAInstruction invoke,
			TabulationDomain<TaintDomainElement, BasicBlockInContext<IExplodedBasicBlock>> domain, IntSet facts,
			HashMap<String, MutableSparseIntSet> type2facts) {
		facts.foreach(x -> {
			if (x == 0)
				return;

			boolean used = false;
			TaintDomainElement de = domain.getMappedObject(x);
			AccessPath ap = de.getAccessPath();
			int vn = ap.getBase();
			for (int i = 0; i < invoke.getNumberOfUses(); i++) {
				if (invoke.getUse(i) == vn) {
					used = true;
					break;
				}
			}
			if (used) {
				String type = de.getSource().getType();
				if (!type2facts.containsKey(type))
					type2facts.put(type, MutableSparseIntSet.makeEmpty());
				type2facts.get(type).add(x);
			}
		});
	}

	private static boolean isWrite2Response(BasicBlockInContext<IExplodedBasicBlock> bblock, int vn,
			ISupergraph<BasicBlockInContext<IExplodedBasicBlock>, CGNode> icfgs,
			Map<IExplodedBasicBlock, Set<Pair<Integer, Boolean>>> writeRes_visited) {
		if (writeRes_visited.containsKey(bblock.getDelegate())) {
			for (Pair<Integer, Boolean> pair : writeRes_visited.get(bblock.getDelegate())) {
				if (pair.fst == vn)
					return pair.snd;
			}
		}
		if (!writeRes_visited.containsKey(bblock.getDelegate()))
			writeRes_visited.put(bblock.getDelegate(), new HashSet<>());
		writeRes_visited.get(bblock.getDelegate()).add(Pair.make(vn, false));

		ExplodedControlFlowGraph cfg = ExplodedControlFlowGraph.make(bblock.getNode().getIR());

		Set<IExplodedBasicBlock> hasVisited = new HashSet<>();
		Queue<IExplodedBasicBlock> queue = new LinkedList<>(); // to deal list
		HashMap<IExplodedBasicBlock, Integer> ebb2def = new HashMap<>();

		int begin = -1;
		int end = -1;
		/* 1. check this node with given vn */
		queue.add(bblock.getDelegate());
		while (!queue.isEmpty()) {
			IExplodedBasicBlock head = queue.remove();
			if (hasVisited.contains(head))
				continue;
			hasVisited.add(head);

			SSAInstruction currInst = head.getLastInstruction();
			if (currInst != null && currInst instanceof SSAConditionalBranchInstruction) {
				SSAConditionalBranchInstruction branchInst = (SSAConditionalBranchInstruction) currInst;
				end = branchInst.getTarget();
				begin = head.getNumber();
			}

			// check current ebb
			if (head.getNumber() <= begin || head.getNumber() >= end)
				if (AuthenticationUtil.isEbbUsed(head, vn)) {
					if (currInst instanceof SSAInvokeInstruction) {
						if (((SSAInvokeInstruction) currInst).getDeclaredTarget().getSignature()
								.startsWith("javax.servlet.http.Cookie.<init>")) {
							writeRes_visited.get(bblock.getDelegate()).remove(Pair.make(vn, false));
							writeRes_visited.get(bblock.getDelegate()).add(Pair.make(vn, true));
							return true;
						}
					}
					// record <bb,def> when def = bb.inst.use(vn)
					if (currInst != null) {
						int def = currInst.getDef();
						if (def > 0) {
							ebb2def.put(head, def);
						}
					}
				}

			// intra-procedure: find immediate next ebb in this cgnode
			Iterator<IExplodedBasicBlock> iterator = cfg.getSuccNodes(head);
			while (iterator.hasNext()) {
				IExplodedBasicBlock succ = iterator.next();
				queue.add(succ);
			}
		}

		/* 2. check the callsite node with the value number mapped from vn */
		// deal with: {c.foo(vn); writeRes(vn);} foo(vn){savebb(vn)}, currbb = savebb
		// find callsite ebb in caller
		boolean iswrite = false;
		for (BasicBlockInContext<IExplodedBasicBlock> entry : icfgs.getEntriesForProcedure(bblock.getNode())) {
			Iterator<BasicBlockInContext<IExplodedBasicBlock>> it = icfgs.getPredNodes(entry);
			while (it.hasNext()) {
				BasicBlockInContext<IExplodedBasicBlock> cs = it.next();
				if (cs.getLastInstruction() instanceof SSAInvokeInstruction) {
					SSAInvokeInstruction invoke = (SSAInvokeInstruction) cs.getLastInstruction();
					HashSet<Integer> vns = new HashSet<>();
					if (invoke.getNumberOfUses() < vn) {
						HashSet<Integer> visitedDefs = new HashSet<>();
						findDefInNode(bblock.getNode().getDU(), vn, vns, invoke.getNumberOfUses(), visitedDefs);
					} else {
						vns.add(vn);
					}
					for (int i : vns) {
						int newVn = invoke.getUse(i - 1);
						iswrite = isWrite2Response(cs, newVn, icfgs, writeRes_visited);
						if (iswrite)
							return true;
					}
				}
			}
		}

		/* 3. check the variable defined in this node from vn */
		for (Entry<IExplodedBasicBlock, Integer> ele : ebb2def.entrySet()) {
			iswrite = isWrite2Response(new BasicBlockInContext<IExplodedBasicBlock>(bblock.getNode(), ele.getKey()),
					ele.getValue(), icfgs, writeRes_visited);
			if (iswrite)
				return true;
		}
		return false;
	}

	private static void findDefInNode(DefUse du, int vn, HashSet<Integer> vns, int max, HashSet<Integer> visitedDefs) {
		SSAInstruction defInst = du.getDef(vn);
		visitedDefs.add(vn);
		if (defInst == null)
			return;
		for (int i = 0; i < defInst.getNumberOfUses(); i++) {
			int defVn = defInst.getUse(i);
			if (defVn > max) {
				if (!visitedDefs.contains(defVn))
					findDefInNode(du, defVn, vns, max, visitedDefs);
			} else
				vns.add(defVn);
		}
	}

}
