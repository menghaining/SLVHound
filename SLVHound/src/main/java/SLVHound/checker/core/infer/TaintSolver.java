package SLVHound.checker.core.infer;

import com.ibm.wala.dataflow.IFDS.TabulationResult;
import com.ibm.wala.dataflow.IFDS.TabulationSolver;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.util.CancelException;

import SLVHound.checker.core.infer.dataflow.TaintDomainElement;
import SLVHound.checker.core.infer.dataflow.TaintProblem;

public class TaintSolver {
	TaintProblem problem;

	public TaintSolver(TaintProblem problem) {
		this.problem = problem;
	}

	TabulationResult<BasicBlockInContext<IExplodedBasicBlock>, CGNode, TaintDomainElement> result = null;

	public TabulationResult<BasicBlockInContext<IExplodedBasicBlock>, CGNode, TaintDomainElement> getResult() {
		return result;
	}

	public void run() {
		TabulationSolver<BasicBlockInContext<IExplodedBasicBlock>, CGNode, TaintDomainElement> solver = TabulationSolver
				.make(problem);
		try {
			result = solver.solve();
		} catch (CancelException e) {
			e.printStackTrace();
		}
	}

}
