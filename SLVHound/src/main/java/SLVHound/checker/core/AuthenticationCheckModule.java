package SLVHound.checker.core;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Set;

import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ssa.DefUse;
import com.ibm.wala.ssa.SSAGetInstruction;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAInvokeInstruction;
import com.ibm.wala.types.ClassLoaderReference;

import SLVHound.checker.core.Util.RepoElement;
import SLVHound.checker.core.db.DBHelper;

public class AuthenticationCheckModule {
	/**
	 * check whether given SSOs maintain @param authRepo</br>
	 * add all not maintained SSOs into @param rets.
	 */
	public static void checkSSOAuthRepoMaintain(RepoElement authRepo, Set<CGNode> nodes, CallGraph cg,
			HashSet<CGNode> rets) {
		HashMap<CGNode, Boolean> visited = new HashMap<>(); // intra-procedural
		for (CGNode node : nodes) {
			checkMaintain(visited, node, authRepo);
			boolean maintain = visited.get(node);

			if (!maintain) {
				Queue<CGNode> queue_caller = new LinkedList<>();// only up
				Queue<CGNode> queue_callee = new LinkedList<>();// only down
				queue_caller.add(node);
				queue_callee.add(node);

				// calculate up
				while (!queue_caller.isEmpty()) {
					CGNode caller = queue_caller.remove();
					if (!caller.equals(node)) {
						if (visited.containsKey(caller)) {
							if (visited.get(caller)) {
								maintain = true;
								break;
							}
							continue;
						}
						checkMaintain(visited, caller, authRepo);
						if (visited.get(caller)) {
							maintain = true;
							break;
						}
					}

					// calculate callers
					Iterator<CGNode> callers = cg.getPredNodes(caller);
					if (callers != null)
						callers.forEachRemaining(ccaller -> {
							if (ccaller.getMethod().getDeclaringClass().getClassLoader().getReference()
									.equals(ClassLoaderReference.Application))
								queue_caller.add(ccaller);
						});
					// calculate callees
					Iterator<CGNode> callees = cg.getSuccNodes(caller);
					if (callees != null)
						callees.forEachRemaining(callee -> {
							if (callee.getMethod().getDeclaringClass().getClassLoader().getReference()
									.equals(ClassLoaderReference.Application))
								queue_callee.add(callee);
						});
				}
				// calculate down
				while (!queue_callee.isEmpty()) {
					CGNode callee = queue_callee.remove();
					if (!callee.equals(node)) {
						if (visited.containsKey(callee)) {
							if (visited.get(callee)) {
								maintain = true;
								break;
							}
							continue;
						}
						checkMaintain(visited, callee, authRepo);
						if (visited.get(callee)) {
							maintain = true;
							break;
						}
					}
					// calculate callees
					Iterator<CGNode> callees = cg.getSuccNodes(callee);
					if (callees != null)
						callees.forEachRemaining(calleecallee -> {
							if (calleecallee.getMethod().getDeclaringClass().getClassLoader().getReference()
									.equals(ClassLoaderReference.Application))
								queue_callee.add(calleecallee);
						});
				}
			}
			if (maintain) {
//				System.out.println(node.getMethod().getSignature() + " maintained after modifying");
			} else {
				rets.add(node);
//				System.out.println(
//						"[AUTHENTICATION BUG]" + node.getMethod().getSignature() + " not maintained after modifying");
			}
		}
	}

	/**
	 * check intra-procedural for given SSO
	 * 
	 * 
	 */
	private static void checkMaintain(HashMap<CGNode, Boolean> visited, CGNode node, RepoElement authRepo) {
		visited.put(node, false);
		if (node.getIR() == null || node.getIR().getInstructions() == null
				|| node.getIR().getInstructions().length == 0)
			return;

		/* calculate this node */
		// delete session op1: session.invalid
		// delete session op2: SecurityUtils.getSubject().logout()
		node.getIR().iterateAllInstructions().forEachRemaining(inst -> {
			if (inst != null && (inst instanceof SSAInvokeInstruction)) {
				SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;
				if (!invoke.isStatic()) {
					String calleeSig = invoke.getDeclaredTarget().getSignature();
					if (calleeSig.startsWith("javax.servlet.http.HttpSession.invalidate")
							|| calleeSig.startsWith("org.apache.shiro.subject.Subject.logout")
							|| calleeSig.startsWith("org.apache.shiro.session.Session.stop")
							|| calleeSig.startsWith("org.apache.shiro.mgt.DefaultSecurityManager.logout")
							|| calleeSig.startsWith(
									"org.springframework.security.core.session.SessionInformation.expireNow")
							|| calleeSig.startsWith(
									"org.springframework.web.context.request.ServletRequestAttributes.removeAttribute")) {
						visited.put(node, true);
						return;
					}
				} else {
					String calleeSig = invoke.getDeclaredTarget().getSignature();
					if (calleeSig.startsWith("com.fujieid.jap.core.context.JapAuthentication.logout")) {
						visited.put(node, true);
						return;
					}
				}
			}
		});

		/* delete session op2: remove from db */
		// e.g. authRepo: RedisCommand.redisHashOps:HashOperations
		node.getIR().iterateAllInstructions().forEachRemaining(inst -> {
			if (inst != null && (inst instanceof SSAInvokeInstruction)) {
				SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;
				if (!invoke.isStatic()) {
					String mtdName = invoke.getDeclaredTarget().getName().toString();
					// TODO: more action
					// which operations?
					if (DBHelper.instance().canCastSame(invoke.getDeclaredTarget().getDeclaringClass(),
							authRepo.getBaseType(), node.getClassHierarchy())) {
						if (mtdName.toLowerCase().startsWith("delete")) {
							int base = invoke.getUse(0);
							DefUse du = node.getDU();
							SSAInstruction basedefInst = du.getDef(base);
							if (basedefInst instanceof SSAGetInstruction) {
								String name = ((SSAGetInstruction) basedefInst).getDeclaredField().getName().toString();
								// TODO: whether or not
								// which object name?
								if (name.equals(authRepo.getName())) {
									visited.put(node, true);
									return;
								}
								// if is redis db, think as single mode
								if (DBHelper.instance().isRedisDBClass(
										authRepo.getBaseType().getName().toString().substring(1).replace('/', '.'))) {
									visited.put(node, true);
									return;
								}
							}
							if (authRepo.getName().equals(RepoElement.shiro)
									|| authRepo.getName().equals(RepoElement.springsecurity)) {
								visited.put(node, true);
								return;
							}
						}
					}
				}
			}
		});
	}

	public static boolean isExpireOp(SSAInvokeInstruction invoke, CGNode node, RepoElement authRepo) {
		if (!invoke.isStatic()) {
			String calleeSig = invoke.getDeclaredTarget().getSignature();
			if (calleeSig.startsWith("javax.servlet.http.HttpSession.invalidate")
					|| calleeSig.startsWith("org.apache.shiro.subject.Subject.logout")
					|| calleeSig.startsWith("org.apache.shiro.session.Session.stop")
					|| calleeSig.startsWith("org.apache.shiro.mgt.DefaultSecurityManager.logout")
					|| calleeSig.startsWith("org.springframework.security.core.session.SessionInformation.expireNow")
					|| calleeSig.startsWith(
							"org.springframework.web.context.request.ServletRequestAttributes.removeAttribute")) {
				return true;
			}

			String mtdName = invoke.getDeclaredTarget().getName().toString();
			if (DBHelper.instance().canCastSame(invoke.getDeclaredTarget().getDeclaringClass(), authRepo.getBaseType(),
					node.getClassHierarchy())) {
				if (mtdName.toLowerCase().startsWith("delete")) {
					int base = invoke.getUse(0);
					DefUse du = node.getDU();
					SSAInstruction basedefInst = du.getDef(base);
					if (basedefInst instanceof SSAGetInstruction) {
						String name = ((SSAGetInstruction) basedefInst).getDeclaredField().getName().toString();
						if (name.equals(authRepo.getName())) {
							return true;
						}
						if (DBHelper.instance().isRedisDBClass(
								authRepo.getBaseType().getName().toString().substring(1).replace('/', '.'))) {
							return true;
						}
					}
					if (authRepo.getName().equals(RepoElement.shiro)
							|| authRepo.getName().equals(RepoElement.springsecurity)) {
						return true;
					}
				}
			}
		} else {
			String calleeSig = invoke.getDeclaredTarget().getSignature();
			if (calleeSig.startsWith("com.fujieid.jap.core.context.JapAuthentication.logout")) {
				return true;
			}
		}

		return false;
	}

}
