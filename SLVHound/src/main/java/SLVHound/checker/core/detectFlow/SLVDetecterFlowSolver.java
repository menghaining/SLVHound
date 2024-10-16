package SLVHound.checker.core.detectFlow;

import com.ibm.wala.dataflow.IFDS.TabulationResult;
import com.ibm.wala.dataflow.IFDS.TabulationSolver;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.util.CancelException;
import com.ibm.wala.util.intset.IntIterator;
import com.ibm.wala.util.intset.IntSet;

public class SLVDetecterFlowSolver {
	SLVDetecterManager manager;

	public SLVDetecterFlowSolver(SLVDetecterManager manager) {
		this.manager = manager;
	}

	public void solve() {
		/* 1. set expire as source, check ASO */
		SLVDetecterFlowProblem problem = new SLVDetecterFlowProblem(manager);
		TabulationSolver<BasicBlockInContext<IExplodedBasicBlock>, CGNode, SLVDetecterDomainElement> solver = TabulationSolver
				.make(problem);
		try {
			// forward
			TabulationResult<BasicBlockInContext<IExplodedBasicBlock>, CGNode, SLVDetecterDomainElement> result1 = solver
					.solve();
		} catch (CancelException e) {
			e.printStackTrace();
		}

		/* 2. set ASO as source, check session expire */

	}

	public void analyzeLogout(
			TabulationResult<BasicBlockInContext<IExplodedBasicBlock>, CGNode, SLVDetecterDomainElement> result) {
		boolean report = true;
		// logout
		BasicBlockInContext<IExplodedBasicBlock>[] exits = manager.isg.getExitsForProcedure(manager.ASOEntry);
		if (exits != null) {
			for (BasicBlockInContext<IExplodedBasicBlock> exit : exits) {
				IntSet facts = result.getResult(exit);
				if (facts != null) {
					IntIterator it = facts.intIterator();
					while (it.hasNext()) {
						int x = it.next();
						if (manager.domain.getMappedObject(x).type.equals(SLVDetecterDomainType.expire)) {
							report = false;
							break;
						}
					}
				}
			}
		}
		if (report)
			System.out.println("[SLV] " + manager.ASOEntry);
	}

}
