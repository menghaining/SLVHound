package SLVHound.checker.core.infer.dataflow;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import com.ibm.wala.dataflow.IFDS.IMergeFunction;
import com.ibm.wala.dataflow.IFDS.IPartiallyBalancedFlowFunctions;
import com.ibm.wala.dataflow.IFDS.ISupergraph;
import com.ibm.wala.dataflow.IFDS.PartiallyBalancedTabulationProblem;
import com.ibm.wala.dataflow.IFDS.PathEdge;
import com.ibm.wala.dataflow.IFDS.TabulationDomain;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;

public class TaintProblem implements
		PartiallyBalancedTabulationProblem<BasicBlockInContext<IExplodedBasicBlock>, CGNode, TaintDomainElement> {
	TaintManager manager;
	

	public TaintProblem(TaintManager manager) {
		this.manager = manager;
		this.flowFunctions = new TaintFlowFunctions(manager);
	}

	@Override
	public TabulationDomain<TaintDomainElement, BasicBlockInContext<IExplodedBasicBlock>> getDomain() {
		return manager.getDomain();
	}

	@Override
	public ISupergraph<BasicBlockInContext<IExplodedBasicBlock>, CGNode> getSupergraph() {
		return manager.getIsg();
	}

	@Override
	public Collection<PathEdge<BasicBlockInContext<IExplodedBasicBlock>>> initialSeeds() {
		Set<PathEdge<BasicBlockInContext<IExplodedBasicBlock>>> initialSeeds = new HashSet<PathEdge<BasicBlockInContext<IExplodedBasicBlock>>>();
		for (CGNode entry : manager.getEntries()) {
			BasicBlockInContext<IExplodedBasicBlock>[] entries = manager.getIsg().getEntriesForProcedure(entry);
			for (int i = 0; i < entries.length; i++) {
				PathEdge<BasicBlockInContext<IExplodedBasicBlock>> initSeed = PathEdge.createPathEdge(entries[i], 0,
						entries[i], 0);
				initialSeeds.add(initSeed);
			}
		}
		return initialSeeds;
	}

	@Override
	public BasicBlockInContext<IExplodedBasicBlock> getFakeEntry(BasicBlockInContext<IExplodedBasicBlock> bb) {
		CGNode node = bb.getNode();
		BasicBlockInContext<IExplodedBasicBlock>[] entriesForProcedure = manager.getIsg().getEntriesForProcedure(node);
		assert entriesForProcedure.length == 1;
		return entriesForProcedure[0];
	}

	@Override
	public IMergeFunction getMergeFunction() {
		return null;
	}

	private final IPartiallyBalancedFlowFunctions<BasicBlockInContext<IExplodedBasicBlock>> flowFunctions;

	@Override
	public IPartiallyBalancedFlowFunctions<BasicBlockInContext<IExplodedBasicBlock>> getFunctionMap() {
		return flowFunctions;
	}

}
