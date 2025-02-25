package SLVHound.checker.core.detectFlow;

import com.ibm.wala.dataflow.IFDS.TabulationResult;
import com.ibm.wala.dataflow.IFDS.TabulationSolver;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.analysis.ExplodedControlFlowGraph;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.util.CancelException;
import com.ibm.wala.util.intset.IntIterator;
import com.ibm.wala.util.intset.IntSet;

public class SLVDetecterFlowSolver {
	SLVDetecterManager manager;

	public SLVDetecterFlowSolver(SLVDetecterManager manager) {
		this.manager = manager;
	}

	public boolean solve() {
		boolean vuln1 = false;
		boolean vuln2 = false;
		try {
			/* 1. set expire as source, check ASO */
			SLVDetecterFlowProblem problem1 = new SLVDetecterFlowProblem(manager);
			TabulationSolver<BasicBlockInContext<IExplodedBasicBlock>, CGNode, SLVDetecterDomainElement> solver = TabulationSolver
					.make(problem1);
			TabulationResult<BasicBlockInContext<IExplodedBasicBlock>, CGNode, SLVDetecterDomainElement> result_forward = solver
					.solve();

			/* 2. set ASO as source, check session expire */
			manager.setBackward();
			SLVDetecterFlowProblem problem2 = new SLVDetecterFlowProblem(manager);
			TabulationSolver<BasicBlockInContext<IExplodedBasicBlock>, CGNode, SLVDetecterDomainElement> solver2 = TabulationSolver
					.make(problem2);
			TabulationResult<BasicBlockInContext<IExplodedBasicBlock>, CGNode, SLVDetecterDomainElement> result_backward = solver2
					.solve();

			// result
			for (SSAInstruction inst : manager.getASOs()) {
				ExplodedControlFlowGraph cfg = ExplodedControlFlowGraph.make(manager.ASOEntry.getIR());
				IExplodedBasicBlock ebb = cfg.getContainingExplodedBasicBlock(inst);
				if (ebb != null) {
					BasicBlockInContext<IExplodedBasicBlock> bb = new BasicBlockInContext<IExplodedBasicBlock>(
							manager.ASOEntry, ebb);
					IntSet facts1 = result_forward.getResult(bb);
					if (unchecked(facts1,SLVDetecterDomainType.expire))
						vuln1 = true;
				}
			}
			BasicBlockInContext<IExplodedBasicBlock>[] exits = manager.isg.getExitsForProcedure(manager.ASOEntry);
			if (exits != null) {
				for (BasicBlockInContext<IExplodedBasicBlock> exit : exits) {
					IntSet facts2 = result_backward.getResult(exit);
					if (unchecked(facts2,SLVDetecterDomainType.ASO))
						vuln1 = true;
				}
			}

		} catch (CancelException e) {
			e.printStackTrace();
		}

		return (vuln1 && vuln2);
	}

	private boolean unchecked(IntSet facts, SLVDetecterDomainType type) {
		if (facts != null) {
			IntIterator it = facts.intIterator();
			while (it.hasNext()) {
				int x = it.next();
				if (manager.domain.getMappedObject(x).type.equals(type)) {
					return false;
				}
			}
		}
		return true;
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
