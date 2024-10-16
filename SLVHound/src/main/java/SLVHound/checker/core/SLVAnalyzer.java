package SLVHound.checker.core;

import java.io.IOException;
import java.util.HashSet;

import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.propagation.InstanceKey;
import com.ibm.wala.ipa.callgraph.propagation.PointerAnalysis;
import com.ibm.wala.ipa.callgraph.propagation.SSAPropagationCallGraphBuilder;

import SLVHound.checker.core.Util.UserVar;
import SLVHound.checker.core.db.DBHelper;

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
		AuthCollecter.collectLoginsAndFilters(cg);

		/** 2. analyze login to infer authentication columns **/
		/* 1. custom login */
//		LoginAnalyzer.analyzeNormalLogin(); // taint analysis

		/* 2. spring security */
		/* 3. apache shiro */
		HashSet<UserVar> uservs = LoginAnalyzer.analyzeFrameworkLogin(AuthCollecter.loginMtds, cg);

		/* 4. filters */
		FilterAnalyzer.analyze(AuthCollecter.filterNodes);

		/** 3. identify ASOs **/
		/** 4. detect SLVs **/
		long startDetectrTime = System.currentTimeMillis();
		for (UserVar ele : uservs) {
			ASOCollecter.collect(ele, cg);

			/* 1. exists session expire? */

			/* 2. dataflow check reachable? */

//			SLVDetecterManager manager = new SLVDetecterManager(cg, entry, null);
//			SLVDetecterFlowSolver solver = new SLVDetecterFlowSolver(manager);
//			solver.solve();
		}
		long endDetectrTime = System.currentTimeMillis();
		System.out.println("Detect cost：" + ((double) (endDetectrTime - startDetectrTime) / 1000) + " seconds");
	}

}
