package SLVHound.checker.core;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map.Entry;
import java.util.Set;

import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.propagation.InstanceKey;
import com.ibm.wala.ipa.callgraph.propagation.PointerAnalysis;
import com.ibm.wala.ipa.callgraph.propagation.SSAPropagationCallGraphBuilder;
import com.ibm.wala.ssa.SSAInstruction;
import SLVHound.checker.core.Util.RepoElement;
import SLVHound.checker.core.Util.SSOEnum;
import SLVHound.checker.core.Util.UserVar;
import SLVHound.checker.core.db.DBHelper;
import SLVHound.checker.core.detectFlow.SLVDetecterFlowSolver;
import SLVHound.checker.core.detectFlow.SLVDetecterManager;

public class SLVAnalyzer {
	CallGraph cg;
	PointerAnalysis<InstanceKey> pa;
	String app;
	SSAPropagationCallGraphBuilder builder;

	public SLVAnalyzer(SSAPropagationCallGraphBuilder builder, String appPath) {
		this.builder = builder;
		this.cg = builder.getCallGraph();
		this.pa = builder.getPointerAnalysis();
		this.app = appPath;
	}

	public void analyze() throws IOException {
		long startTime = System.currentTimeMillis();
		DBHelper.init(app, cg);

		/** 1. recognize all login methods and filters */
		AuthCollecter.collectLoginsAndFilters(cg, 0);

		/** 2. analyze login to infer authentication columns **/
		HashMap<RepoElement, HashSet<UserVar>> auth2userMap = LoginAnalyzer.analyze(AuthCollecter.loginMtds,
				AuthCollecter.filterNodes, cg, app);

		/** 3. identify ASOs **/
		HashMap<SSOEnum, HashMap<CGNode, HashSet<SSAInstruction>>> type2SSOs = new HashMap<SSOEnum, HashMap<CGNode, HashSet<SSAInstruction>>>();
		for (Entry<RepoElement, HashSet<UserVar>> pair : auth2userMap.entrySet()) {
			RepoElement authRepo = pair.getKey();
			for (UserVar val : auth2userMap.get(authRepo)) {
				type2SSOs = ASOCollecter.collect(authRepo, val.table2Cloumns, cg);
			}
		}

		/** 4. detect SLVs **/
		HashSet<RepoElement> checkedAuthRepos = new HashSet<>();
		for (CGNode node : AuthCollecter.filterNodes) {
			FilterFinder.getSingleChecked(node, checkedAuthRepos, cg);
		}
		HashMap<RepoElement, HashSet<CGNode>> result = new HashMap<>();
		for (RepoElement authtk : auth2userMap.keySet()) {
			HashSet<CGNode> vulns = new HashSet<>();
			if (checked(checkedAuthRepos, authtk)) {
				for (Entry<SSOEnum, HashMap<CGNode, HashSet<SSAInstruction>>> pair : type2SSOs.entrySet()) {
					HashSet<CGNode> rets1 = new HashSet<>();
					// 1. pre check
					AuthenticationCheckModule.checkSSOAuthRepoMaintain(authtk, pair.getValue().keySet(), cg, rets1);
					vulns.addAll(rets1);
					// 2. check
					Set<CGNode> unknown = new HashSet<>(pair.getValue().keySet());
					unknown.removeAll(rets1);
					for (CGNode entry : unknown) {
						SLVDetecterManager manager = new SLVDetecterManager(cg, entry, pair.getValue().get(entry),
								authtk);
						SLVDetecterFlowSolver solver = new SLVDetecterFlowSolver(manager);
						boolean vuln = solver.solve();
						if (vuln)
							vulns.add(entry);
					}
				}
			} else if (authtk.equals(RepoElement.frmkEle)) {
			}
			if (!vulns.isEmpty())
				result.put(authtk, vulns);
		}
		long endDetectrTime = System.currentTimeMillis();
		System.out.println("Total cost：" + ((double) (endDetectrTime - startTime) / 1000) + " seconds");
	}

	private boolean checked(HashSet<RepoElement> checkedAuthRepos, RepoElement authRepo) {
		for (RepoElement checked : checkedAuthRepos) {
			if ((checked.inject && authRepo.inject && (checked.getBaseType().equals(authRepo.getBaseType())))
					|| checked.getBelong2Class().equals(authRepo.getBelong2Class())) {
				return true;
			}
		}
		return false;
	}

}
