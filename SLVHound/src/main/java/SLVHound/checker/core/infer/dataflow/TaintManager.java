package SLVHound.checker.core.infer.dataflow;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import com.ibm.wala.dataflow.IFDS.ICFGSupergraph;
import com.ibm.wala.dataflow.IFDS.ISupergraph;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAInvokeInstruction;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;

import SLVHound.checker.core.db.DBHelper;

public class TaintManager {

	CallGraph callgraph;
	ISupergraph<BasicBlockInContext<IExplodedBasicBlock>, CGNode> isg;

	TaintDomain domain;

	HashSet<CGNode> entries;

	public TaintManager(CallGraph cg, HashSet<CGNode> nodes) {
		callgraph = cg;

		isg = ICFGSupergraph.make(callgraph);
		domain = new TaintDomain(TaintDomainElement.ZERO);
		entries = nodes;

		initializeAuthenticationSources(entries, collectAuthenticationBBSources(entries, cg, isg));
	}

	public HashSet<CGNode> getEntries() {
		return entries;
	}

	public CallGraph getCallgraph() {
		return callgraph;
	}

	public ISupergraph<BasicBlockInContext<IExplodedBasicBlock>, CGNode> getIsg() {
		return isg;
	}

	public TaintDomain getDomain() {
		return domain;
	}

	private Set<BasicBlockInContext<IExplodedBasicBlock>> authenticationSessionSrcs = new HashSet<>();

	public Set<BasicBlockInContext<IExplodedBasicBlock>> getAuthenticationSessionSrcs() {
		return authenticationSessionSrcs;
	}

	private Set<BasicBlockInContext<IExplodedBasicBlock>> authenticationFindDBSrc = new HashSet<>();

	public Set<BasicBlockInContext<IExplodedBasicBlock>> getAuthenticationFindDBSrc() {
		return authenticationFindDBSrc;
	}

	private Set<String> authenticationParaSourceMethods = new HashSet<String>();

	public Set<String> getAuthenticationParamSourceMethods() {
		return authenticationParaSourceMethods;
	}

	/**
	 * 1. param: login parameters</br>
	 * 2. find: reachable find DBs from login methods </br>
	 * 3. session: system session creation site
	 * 
	 * @param icfg
	 **/
	private void initializeAuthenticationSources(HashSet<CGNode> mayLoginMethods,
			HashMap<String, HashSet<BasicBlockInContext<IExplodedBasicBlock>>> map) {

		for (CGNode node : mayLoginMethods)
			authenticationParaSourceMethods.add(node.getMethod().getSignature());

		if (map.containsKey("session") && !map.get("session").isEmpty())
			authenticationSessionSrcs.addAll(map.get("session"));

		if (map.containsKey("findDB") && !map.get("findDB").isEmpty())
			authenticationFindDBSrc.addAll(map.get("findDB"));
	}

	private HashMap<String, HashSet<BasicBlockInContext<IExplodedBasicBlock>>> collectAuthenticationBBSources(
			HashSet<CGNode> mayLoginMethods, CallGraph cg,
			ISupergraph<BasicBlockInContext<IExplodedBasicBlock>, CGNode> icfg) {
		HashMap<String, HashSet<BasicBlockInContext<IExplodedBasicBlock>>> res = new HashMap<String, HashSet<BasicBlockInContext<IExplodedBasicBlock>>>();
		res.put("findDB", new HashSet<>());
		res.put("session", new HashSet<>());

		HashSet<CGNode> visited = new HashSet<>();
		HashSet<CGNode> result = new HashSet<>();
		for (CGNode node : mayLoginMethods) {
			collectNodes(node, result, cg, visited);
		}

		for (BasicBlockInContext<IExplodedBasicBlock> bb : icfg) {
			if (!result.contains(bb.getNode()))
				continue;
			SSAInstruction inst = bb.getLastInstruction();
			if (inst instanceof SSAInvokeInstruction) {
				SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;
				// 1. session
				if (invoke.getDeclaredTarget().getSignature()
						.equals("javax.servlet.http.HttpSession.getId()Ljava/lang/String;")) {
					res.get("session").add(bb);
				}

				// 2. findDB
				if (DBHelper.instance().isAction2DBAgentInvoke(bb.getNode(), invoke, "get")) {
					res.get("findDB").add(bb);
				}
			}
		}

		return res;
	}

	private void collectNodes(CGNode node, HashSet<CGNode> result, CallGraph cg, HashSet<CGNode> visited) {
		if (visited.contains(node))
			return;
		visited.add(node);

		if (node.getIR() != null) {
			for (SSAInstruction inst : node.getIR().getInstructions()) {
				if (inst instanceof SSAInvokeInstruction) {
					SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;
					// 1. session
					if (invoke.getDeclaredTarget().getSignature()
							.equals("javax.servlet.http.HttpSession.getId()Ljava/lang/String;")) {
						result.add(node);
					}

					// 2. findDB
					if (DBHelper.instance().isAction2DBAgentInvoke(node, invoke, "get")) {
						result.add(node);
					}

					for (CGNode callee : cg.getPossibleTargets(node, invoke.getCallSite())) {
						collectNodes(callee, result, cg, visited);
					}
				}
			}
		}

	}

}
