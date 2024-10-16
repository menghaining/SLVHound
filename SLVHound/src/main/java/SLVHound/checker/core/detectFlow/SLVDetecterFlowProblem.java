package SLVHound.checker.core.detectFlow;

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
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;

public class SLVDetecterFlowProblem implements
		PartiallyBalancedTabulationProblem<BasicBlockInContext<IExplodedBasicBlock>, CGNode, SLVDetecterDomainElement> {
	SLVDetecterManager manager;
	CGNode ASOEntry;
	CallGraph callgraph;
	ISupergraph<BasicBlockInContext<IExplodedBasicBlock>, CGNode> isg;
	TabulationDomain<SLVDetecterDomainElement, BasicBlockInContext<IExplodedBasicBlock>> domain;

	public SLVDetecterFlowProblem(SLVDetecterManager manager) {
		this.manager = manager;

		this.ASOEntry = manager.ASOEntry;
		this.callgraph = manager.cg;
		this.isg = manager.isg;
		this.domain = manager.domain;

		this.flowFunctions = new SLVDetecterFlowFunctions(manager);
	}

	private final IPartiallyBalancedFlowFunctions<BasicBlockInContext<IExplodedBasicBlock>> flowFunctions;

	@Override
	public IPartiallyBalancedFlowFunctions<BasicBlockInContext<IExplodedBasicBlock>> getFunctionMap() {
		return flowFunctions;
	}

	@Override
	public ISupergraph<BasicBlockInContext<IExplodedBasicBlock>, CGNode> getSupergraph() {
		return isg;
	}

	@Override
	public TabulationDomain<SLVDetecterDomainElement, BasicBlockInContext<IExplodedBasicBlock>> getDomain() {
		return domain;
	}

	@Override
	public IMergeFunction getMergeFunction() {
		return null;
	}

	@Override
	public Collection<PathEdge<BasicBlockInContext<IExplodedBasicBlock>>> initialSeeds() {
		Set<PathEdge<BasicBlockInContext<IExplodedBasicBlock>>> initialSeeds = new HashSet<PathEdge<BasicBlockInContext<IExplodedBasicBlock>>>();
		BasicBlockInContext<IExplodedBasicBlock>[] entries = isg.getEntriesForProcedure(ASOEntry);
		for (int i = 0; i < entries.length; ++i) {
			PathEdge<BasicBlockInContext<IExplodedBasicBlock>> initSeed = PathEdge.createPathEdge(entries[i], 0,
					entries[i], 0);
			initialSeeds.add(initSeed);

		}
		return initialSeeds;
	}

	/**
	 * we use the entry block of the CGNode as the "fake" entry when propagating
	 * from callee to caller with unbalanced parens
	 */
	private BasicBlockInContext<IExplodedBasicBlock> getFakeEntry(final CGNode cgNode) {
		BasicBlockInContext<IExplodedBasicBlock>[] entriesForProcedure = isg.getEntriesForProcedure(cgNode);
		assert entriesForProcedure.length == 1;
		return entriesForProcedure[0];
	}

	@Override
	public BasicBlockInContext<IExplodedBasicBlock> getFakeEntry(BasicBlockInContext<IExplodedBasicBlock> node) {
		final CGNode cgNode = node.getNode();
		return getFakeEntry(cgNode);
	}

}
