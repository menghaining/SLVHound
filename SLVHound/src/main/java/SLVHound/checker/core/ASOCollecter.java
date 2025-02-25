package SLVHound.checker.core;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.ibm.wala.analysis.typeInference.TypeInference;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.ssa.DefUse;
import com.ibm.wala.ssa.IR;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAInvokeInstruction;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.types.TypeName;
import com.ibm.wala.types.TypeReference;
import com.ibm.wala.types.annotations.Annotation;

import SLVHound.checker.common.cgBuilder.CGHelper;
import SLVHound.checker.core.Util.AuthenticationUtil;
import SLVHound.checker.core.Util.FlowHelper;
import SLVHound.checker.core.Util.RepoElement;
import SLVHound.checker.core.Util.SSOEnum;
import SLVHound.checker.core.db.DBHelper;

public class ASOCollecter {
	public static HashMap<SSOEnum, HashMap<CGNode, HashSet<SSAInstruction>>> collect(RepoElement infoRepo,
			HashMap<TypeReference, HashSet<String>> ORMClass2fields, CallGraph cg) {
		HashMap<SSOEnum, HashMap<CGNode, HashSet<SSAInstruction>>> type2SSOs = new HashMap<>();
		type2SSOs.put(SSOEnum.logout, new HashMap<>());
		type2SSOs.put(SSOEnum.delete, new HashMap<>());
		type2SSOs.put(SSOEnum.modify, new HashMap<>());

		HashSet<CGNode> mays = new HashSet<>();
		HashSet<CGNode> alls = new HashSet<>();

		HashSet<CGNode> nodes = new HashSet<>();
//		for (CGNode n : cg) {
		for (CGNode n : cg.getEntrypointNodes()) {
			if (!n.getMethod().getDeclaringClass().getClassLoader().getReference()
					.equals(ClassLoaderReference.Application))
				continue;
			nodes.add(n);
		}

		for (CGNode cgNode : nodes) {
			IR ir = cgNode.getIR();
			if (ir == null)
				continue;
			IMethod mtd = cgNode.getMethod();
			// ------- 1. logout ---------
			if (isLogoutMethod(mtd)) {
				type2SSOs.get(SSOEnum.logout).put(cgNode, null);
				alls.add(cgNode);
			}

			// ---------2 & 3 delete and modify--------------------
			HashSet<CGNode> modifies = new HashSet<>();
			HashSet<SSAInstruction> instructions = new HashSet<>();
			if (findDeleteAndModify(cgNode, infoRepo, ORMClass2fields, cg, modifies, mays, new HashSet<>(),
					instructions)) {
				if (modifies.isEmpty()) {
					type2SSOs.get(SSOEnum.delete).put(cgNode, instructions);
				} else {
					type2SSOs.get(SSOEnum.modify).put(cgNode, instructions);
				}
				alls.add(cgNode);
			}
		}

		// if distinguish create and modify cannot find all any, then add all.
		if (type2SSOs.get(SSOEnum.modify).isEmpty() && !mays.isEmpty()) {
			alls.addAll(mays);
			for (CGNode may : mays) {
				type2SSOs.get(SSOEnum.modify).put(may, null);
			}
		}

		return type2SSOs;
	}

	private static boolean isLogoutMethod(IMethod mtd) {
		String regex = "(?i)\\b(log|sign)?out\\b";
		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(mtd.getName().toString().toLowerCase());
		if (matcher.matches()) {
			if (mtd.getName().toString().toLowerCase().equals("out"))
				return false;
			boolean isConfig = false;
			// if mtd in @Configuration Class, think it as configuration
			IClass clazz = mtd.getDeclaringClass();
			if (clazz != null && clazz.getAnnotations() != null) {
				for (Annotation anno : clazz.getAnnotations()) {
					TypeName name = anno.getType().getName();
					if (name.toString().equals("Lorg/springframework/context/annotation/Configuration")) {
						isConfig = true;
						break;
					}
				}
			}
			if (!isConfig)
				return true;
		}
		return false;
	}

	private static boolean findDeleteAndModify(CGNode cgNode, RepoElement infoRepo,
			HashMap<TypeReference, HashSet<String>> ORMClass2fields, CallGraph cg, HashSet<CGNode> modifies,
			HashSet<CGNode> mays, HashSet<CGNode> visited, HashSet<SSAInstruction> instresult) {
		if (visited.contains(cgNode))
			return false;
		visited.add(cgNode);
		if (!cgNode.getMethod().getDeclaringClass().getClassLoader().getReference()
				.equals(ClassLoaderReference.Application))
			return false;
		IR ir = cgNode.getIR();
		if (ir == null)
			return false;

		HashSet<SSAInvokeInstruction> invokes = new HashSet<>();
		// current method
		IMethod mtd = cgNode.getMethod();
		for (SSAInstruction inst : cgNode.getIR().getInstructions()) {
			if (inst instanceof SSAInvokeInstruction) {
				SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;
				invokes.add(invoke);
				if (!invoke.isStatic()) {
					String mtdname = invoke.getDeclaredTarget().getSelector().getName().toString();
					if (mtdname.toLowerCase().startsWith("find") || mtdname.toLowerCase().startsWith("get"))
						continue;

					/* is using DB type */
					TypeReference cr = invoke.getDeclaredTarget().getDeclaringClass();
					IClassHierarchy cha = cg.getClassHierarchy();
					if (cr.getName().toString().equals("Ljava/lang/Object"))
						continue;
//					if ((!AuthenticationUtil.canAssignableFrom(cr, infoRepo.getBaseType(), cha)
//							&& !AuthenticationUtil.canAssignableFrom(infoRepo.getBaseType(), cr, cha)
//							&& !AuthenticationUtil.canAssignableFrom(cr, infoRepo.getBelong2Class().getReference(), cha)
//							&& !AuthenticationUtil.canAssignableFrom(infoRepo.getBelong2Class().getReference(), cr,
//									cha))) {
//						continue;
//					}
					if ((!AuthenticationUtil.canAssignableFrom(cr, infoRepo.getBaseType(), cha) && !AuthenticationUtil
							.canAssignableFrom(cr, infoRepo.getBelong2Class().getReference(), cha))) {
						continue;
					}
//					if ((infoRepo.belong2Class instanceof PhantomClass) && !infoRepo.getBaseType().equals(cr))
//						continue;
					if (invoke.getDeclaredTarget().isInit())
						continue;

					// special deal with javaeeAPI
					if (DBHelper.instance().isJavaEEAPIEMClass(
							infoRepo.getBaseType().getName().toString().replace('/', '.').substring(1))) {
						if (AuthenticationUtil.canAssignableFrom(cr, infoRepo.getBelong2Class().getReference(), cha)) {
							// the next is execute db action
							// find the table
							for (int i = 1; i < invoke.getNumberOfUses(); i++) {
								// type
								int useVn = invoke.getUse(i);
								TypeInference inference = TypeInference.make(cgNode.getIR(), false);
								TypeReference paramType = inference.getType(useVn).getTypeReference();
								if (ORMClass2fields.containsKey(paramType)) {
									Set<CGNode> targets = CGHelper.findAllTargets(invoke, cgNode, cg);
									for (CGNode target : targets) {
										Iterator<SSAInstruction> uses = target.getDU().getUses(i + 1);
										while (uses.hasNext()) {
											SSAInstruction use = uses.next();
											if (use instanceof SSAInvokeInstruction) {
												SSAInvokeInstruction inv = (SSAInvokeInstruction) use;
												if (DBHelper.instance()
														.isJavaEEAPIEMClass(inv.getDeclaredTarget().getSignature())) {
													String action = inv.getDeclaredTarget().getName().toString();
													boolean find = false;
													if (action.equals("remove") || action.equals("detach")) {
														instresult.add(inv);
														return true;
													}
													if (action.equals("persist") || action.equals("merge")) {
														modifies.add(cgNode);
														instresult.add(inv);
														return true;
													}
													// TODO: if saved object from db?

													if (find)
														return true;
												}
											}
										}
									}
								}
							}
						}
					}
					// deal with:
					// u.save(); u is interface
					// current base actual type is u1
					// class u1 extends S impements u
					// in S: save();
					if (!invoke.isStatic()) {
						TypeReference declareClazzTR = invoke.getDeclaredTarget().getDeclaringClass();
						IClass declareClazz = cg.getClassHierarchy().lookupClass(declareClazzTR);
						if (declareClazz != null) {
							boolean isSaveDB = false;
							Integer checkobj = -1;
							SSAInvokeInstruction tinvoke = null;
							TypeInference inference = TypeInference.make(cgNode.getIR(), false);
							Set<CGNode> possibleTargets = cg.getPossibleTargets(cgNode, invoke.getCallSite());
							for (CGNode targetNode : possibleTargets) {
								IClass targetclass = targetNode.getMethod().getDeclaringClass();
								if (!cg.getClassHierarchy().isAssignableFrom(targetclass, declareClazz)
										&& !cg.getClassHierarchy().isAssignableFrom(declareClazz, targetclass)) {
									Set<IClass> t1 = new HashSet<>();
									for (IClass tt1 : cg.getClassHierarchy().getImplementors(declareClazzTR))
										t1.add(tt1);
									for (IClass tt1 : cg.getClassHierarchy().computeSubClasses(declareClazzTR))
										t1.add(tt1);

									Set<IClass> t2 = new HashSet<>();
									for (IClass tt2 : cg.getClassHierarchy()
											.getImplementors(targetclass.getReference()))
										t2.add(tt2);
									for (IClass tt2 : cg.getClassHierarchy()
											.computeSubClasses(targetclass.getReference()))
										t2.add(tt2);
									t1.retainAll(t2); // find u1

									if (!t1.isEmpty() && !invoke.isStatic()) {
										HashMap<Integer, TypeReference> vn2Ref = new HashMap<>();
										for (int vn = 2; vn <= invoke.getNumberOfUses(); vn++) {
											int useVn = invoke.getUse(vn - 1);
											TypeReference paramType = inference.getType(useVn).getTypeReference();
											vn2Ref.put(vn, paramType);
										}
										for (SSAInstruction tinst : targetNode.getIR().getInstructions()) {
											if (tinst instanceof SSAInvokeInstruction) {
												tinvoke = (SSAInvokeInstruction) tinst;
												if (DBHelper.instance().isSpringAction(
														tinvoke.getDeclaredTarget().getDeclaringClass().getName()
																.toString(),
														tinvoke.getDeclaredTarget().getName().toString().toLowerCase(),
														"save")) {
													for (int ii = 2; ii <= tinvoke.getNumberOfUses(); ii++) {
														int useVn = tinvoke.getUse(ii - 1);
														if (vn2Ref.containsKey(useVn)) {
															checkobj = useVn;
															isSaveDB = true;
															break;
														}
													}
												}
											}
											if (isSaveDB)
												break;
										}
									}
								}
								if (isSaveDB)
									break;
							}
							if (isSaveDB) {
								if (checkobj > 1) {
									int used = invoke.getUse(checkobj - 1);
									TypeReference key = inference.getType(used).getTypeReference();
									if (key == null)
										continue;
									Iterator<SSAInstruction> it = cgNode.getDU().getUses(used);
									while (it.hasNext()) {
										SSAInstruction ii = it.next();
										if (ii instanceof SSAInvokeInstruction) {
											SSAInvokeInstruction useInvoke = (SSAInvokeInstruction) ii;
											if (useInvoke.isStatic())
												continue;
											String targetMtdName = useInvoke.getDeclaredTarget().getName().toString();
											HashSet<String> fieldsName = ORMClass2fields.get(key);
											for (String name : fieldsName) {
												String tmp = "set" + name.toLowerCase();
												if (targetMtdName.toLowerCase().equals(tmp)) {
													// 2) setted value comes from param
													for (int j = 1; j < useInvoke.getNumberOfUses(); j++) {
														int usedVn = useInvoke.getUse(j);
														HashSet<Integer> visited_tmp = new HashSet<>();
														if (!invoke.isStatic())
															visited_tmp.add(1);
														if (FlowHelper.isVnFlowFromParam_intra(usedVn,
																mtd.getNumberOfParameters(), cgNode.getDU(),
																visited_tmp)) {
															modifies.add(cgNode);
															instresult.add(tinvoke);
															return true;
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}

					// ------- 2. user delete---------
					if (!DBHelper.instance().isDBMethod(invoke, cha))
						continue;

					boolean isDeleteSecuritySensitiveOperation = false;
					if (mtdname.toLowerCase().startsWith("delete") || mtdname.toLowerCase().startsWith("remove"))
						isDeleteSecuritySensitiveOperation = true;
					if (cgNode.getMethod().getName().toString().equals("delete")
							&& mtdname.toLowerCase().startsWith("update"))
						isDeleteSecuritySensitiveOperation = true;
					if (isDeleteSecuritySensitiveOperation) {
						instresult.add(invoke);
						return true;
					}

					// ------- 3. modify user important info -------
					/*
					 * To distinguish `saveDB` in update and createUser operation, we think only the
					 * modify on the object that retrieved from db
					 */
					if (!DBHelper.instance().isAction2DBAgentInvoke(cgNode, invoke, "save"))
						continue;
					if (ORMClass2fields == null)
						continue;
					// calculate the ORM class type
					HashSet<TypeReference> candidateORMclasses = new HashSet<>();
					assert !invoke.isStatic();
					for (int i = 1; i < invoke.getNumberOfUses(); i++) {
						int useVn = invoke.getUse(i);
						TypeInference inference = TypeInference.make(cgNode.getIR(), false);
						TypeReference paramType = inference.getType(useVn).getTypeReference();
						TypeReference key = null;
						for (TypeReference type : ORMClass2fields.keySet()) {
							if (type.equals(paramType)) {
								key = type;
								break;
							} else {
								if (AuthenticationUtil.canAssignableFrom(type, paramType, cha)
										|| AuthenticationUtil.canAssignableFrom(paramType, type, cha)) {
									key = type;
									break;
								}
							}
						}

						if (key != null) {
							// the operated object is from DB
							boolean fromDB = false;
							if (FlowHelper.isFromFindDB(useVn, cgNode, infoRepo.getBaseType(), cg, new HashSet<>())
									|| FlowHelper.isFromFindDB(useVn, cgNode, infoRepo.getBelong2Class().getReference(),
											cg, new HashSet<>())) {
								fromDB = true;
							}
							if (DBHelper.instance().updateExist(invoke.getDeclaredTarget().getSignature()))
								fromDB = true;
							candidateORMclasses.add(key);
							// 3.2 object field
							DefUse du = cgNode.getDU();
							HashSet<SSAInstruction> insts = new HashSet<>();

							SSAInstruction defInst = du.getDef(useVn);
							int vvvv = -2;
							if (defInst != null && defInst.getNumberOfUses() > 0) {
								vvvv = defInst.getUse(0);
								if (vvvv > 0)
									du.getUses(vvvv).forEachRemaining(x -> {
										insts.add(x);
									});
							}

							du.getUses(useVn).forEachRemaining(x -> {
								insts.add(x);
							});
							Iterator<SSAInstruction> it = insts.iterator();
							while (it.hasNext()) {
								SSAInstruction useInst = it.next();
								// 1) user.setPassword() / setAttr()
								if (useInst.getUse(0) != useVn && useInst.getUse(0) != vvvv)
									continue;
								if (useInst instanceof SSAInvokeInstruction) {
									SSAInvokeInstruction useInvoke = (SSAInvokeInstruction) useInst;
									if (useInvoke.isStatic())
										continue;
									String targetMtdName = useInvoke.getDeclaredTarget().getName().toString();
									HashSet<String> fieldsName = ORMClass2fields.get(key);
									for (String name : fieldsName) {
										String tmp = "set" + name.toLowerCase();
										if (targetMtdName.toLowerCase().equals(tmp)) {
											// 2) setted value comes from param
											for (int j = 1; j < useInvoke.getNumberOfUses(); j++) {
												int usedVn = useInvoke.getUse(j);
												HashSet<Integer> visited_tmp = new HashSet<>();
												if (!invoke.isStatic())
													visited_tmp.add(1);
												if (FlowHelper.isVnFlowFromParam_intra(usedVn,
														mtd.getNumberOfParameters(), du, visited_tmp)) {
													if (fromDB) {
														modifies.add(cgNode);
														instresult.add(invoke);
														return true;
													}
													mays.add(cgNode);
												}
											}
										}
									}
								}
							}
						}
					}

					if (candidateORMclasses.size() > 0) {
						// 3.1 query stmt
						List<String> attrs = DBHelper.instance().parseDBstmt2findAttrs(mtdname);
						for (TypeReference paramType : candidateORMclasses) {
							if (attrs.size() > 0) {
								for (String attr : attrs) {
									if (ORMClass2fields.get(paramType).contains(attr)) {
										modifies.add(cgNode);
										return true;
									}
								}
							}
						}
						// for lin-cms
						if (invoke.getDeclaredTarget().getSignature()
								.startsWith("io.github.talelin.latticy.mapper.UserIdentityMapper.update")
								&& cgNode.getMethod().getSignature()
										.contains("UserIdentityServiceImpl.changePassword")) {
							modifies.add(cgNode);
							return true;
						}
					}

				}
			}
		}

		// if not, find in callees
//		for (SSAInvokeInstruction invoke : invokes) {
//			// since  CGHelper.findAllTargets may modify CallGraph, could not use in cg's direct traverse
//			Set<CGNode> callees = CGHelper.findAllTargets(invoke, cgNode, cg);
//			for (CGNode callee : callees) {
//				if (findDeleteAndModify(callee, infoRepo, ORMClass2fields, cg, modifies, mays, visited))
//					return true;
//			}
//		}
		Iterator<CGNode> callees = cg.getSuccNodes(cgNode);
		while (callees.hasNext()) {
			CGNode next = callees.next();
			if (findDeleteAndModify(next, infoRepo, ORMClass2fields, cg, modifies, mays, visited, instresult))
				return true;
		}

		return false;
	}

}
