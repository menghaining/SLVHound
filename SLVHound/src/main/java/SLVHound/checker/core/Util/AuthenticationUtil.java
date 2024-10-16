package SLVHound.checker.core.Util;

import java.util.Collection;
import java.util.Iterator;

import com.ibm.wala.classLoader.BytecodeClass;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IField;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.ssa.DefUse;
import com.ibm.wala.ssa.SSACheckCastInstruction;
import com.ibm.wala.ssa.SSAGetCaughtExceptionInstruction;
import com.ibm.wala.ssa.SSAGetInstruction;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAInvokeInstruction;
import com.ibm.wala.ssa.SSAPhiInstruction;
import com.ibm.wala.ssa.SSAPiInstruction;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.types.FieldReference;
import com.ibm.wala.types.TypeReference;
import com.ibm.wala.types.annotations.Annotation;

import SLVHound.checker.core.db.DBHelper;

/** corresponding to logic */
public class AuthenticationUtil {

	/** whether given bb use the given value number */
	public static boolean isEbbUsed(IExplodedBasicBlock ebb, int value) {
		Iterator<SSAPhiInstruction> phiIterator = ebb.iteratePhis();
		while (phiIterator.hasNext()) {
			SSAPhiInstruction phi = (SSAPhiInstruction) phiIterator.next();
			for (int i = 0; i < phi.getNumberOfUses(); i++) {
				if (phi.getUse(i) == value)
					return true;
			}
		}
		SSAInstruction instruction = ebb.getLastInstruction();
		if (instruction != null) {
			for (int i = 0; i < instruction.getNumberOfUses(); i++) {
				if (instruction.getUse(i) == value)
					return true;
			}
		}
		Iterator<SSAPiInstruction> piIterator = ebb.iteratePis();
		while (piIterator.hasNext()) {
			SSAPiInstruction pi = (SSAPiInstruction) piIterator.next();
			for (int i = 0; i < pi.getNumberOfUses(); i++) {
				if (pi.getUse(i) == value)
					return true;
			}
		}
		if (ebb.isCatchBlock()) {
			SSAGetCaughtExceptionInstruction catchInstruction = ebb.getCatchInstruction();
			if (catchInstruction != null) {
				for (int i = 0; i < catchInstruction.getNumberOfUses(); i++) {
					if (catchInstruction.getUse(i) == value)
						return true;
				}
			}
		}
		return false;
	}

	public static FieldReference extractGetField(BasicBlockInContext<IExplodedBasicBlock> bb) {
		FieldReference ret = null;
		SSAInvokeInstruction inst = (SSAInvokeInstruction) bb.getLastInstruction();
		if (!inst.isStatic()) {
			int base = inst.getUse(0);
			DefUse du = bb.getNode().getDU();
			SSAInstruction defbase = du.getDef(base);
			if (defbase instanceof SSAGetInstruction) {
				SSAGetInstruction getInst = (SSAGetInstruction) defbase;
				ret = getInst.getDeclaredField();
			} else if (defbase instanceof SSACheckCastInstruction) {
				SSACheckCastInstruction castInst = (SSACheckCastInstruction) defbase;
				int casted = castInst.getUse(0);
				SSAInstruction castedDef = du.getDef(casted);
				if (castedDef instanceof SSAGetInstruction) {
					SSAGetInstruction getInst = (SSAGetInstruction) castedDef;
					ret = getInst.getDeclaredField();
				} else if (castedDef instanceof SSAInvokeInstruction) {
					// spring-framework ApplicationContext.getBean
					// todo
				}
			}
		}

		return ret;

	}

//	public static RepoElement buildRepoElement(IClassHierarchy cha, FieldReference fieldRef, BasicBlockInContext<IExplodedBasicBlock> bb) {
//		IField field = cha.resolveField(fieldRef);
//		if (field != null) {
//			boolean inject = false;
//			if (field.getAnnotations() != null) {
//				Iterator<Annotation> it = field.getAnnotations().iterator();
//				while (it.hasNext()) {
//					Annotation anno = it.next();
//					// whether inject or not
//					// TODO: use configuration
//					// TODO: add more
//					if (anno.getType().getName().toString()
//							.equals("Lorg/springframework/beans/factory/annotation/Autowired")) {
//						inject = true;
//						break;
//					}
//				}
//			}
//
//			String fieldName = fieldRef.getName().toString();
//			TypeReference fieldType = fieldRef.getFieldType();
//			IClass declareClass = field.getDeclaringClass();
//			RepoElement ele = new RepoElement(declareClass, fieldType, fieldName, inject, bb);
//			return ele;
//		}
//
//		return null;
//	}

	public static RepoElement buildRepoElement(CallGraph cg, BasicBlockInContext<IExplodedBasicBlock> bb) {
		SSAInvokeInstruction inst = (SSAInvokeInstruction) bb.getLastInstruction();
		if (DBHelper.instance().isJavaEEAPIEMClass(inst.getDeclaredTarget().getSignature())
				|| DBHelper.instance().isMongoDBClass(inst.getDeclaredTarget().getSignature())
				|| DBHelper.instance().isJdbcTemplateClass(inst.getDeclaredTarget().getSignature())) {
			RepoElement ele = new RepoElement(bb.getMethod().getDeclaringClass(),
					inst.getDeclaredTarget().getDeclaringClass(), bb.getMethod().getName().toString(), false, bb);
			return ele;
		}
		if (!inst.isStatic()) {
			int base = inst.getUse(0);
			DefUse du = bb.getNode().getDU();
			SSAInstruction defbase = du.getDef(base);
			if (defbase instanceof SSACheckCastInstruction) {
				defbase = du.getDef(defbase.getUse(0));
			}
			if (defbase instanceof SSAGetInstruction) {
				SSAGetInstruction getInst = (SSAGetInstruction) defbase;
				FieldReference fieldRef = getInst.getDeclaredField();
				IField field = cg.getClassHierarchy().resolveField(fieldRef);
				boolean inject = false;
				String fieldName = getInst.getDeclaredField().getName().toString();
				TypeReference fieldType = getInst.getDeclaredField().getFieldType();
				IClass declareClass = bb.getMethod().getDeclaringClass();
				if (field != null) {
					if (field.getAnnotations() != null) {
						Iterator<Annotation> it = field.getAnnotations().iterator();
						while (it.hasNext()) {
							Annotation anno = it.next();
							// whether inject or not
							// TODO: use configuration
							// TODO: add more
							if (anno.getType().getName().toString()
									.equals("Lorg/springframework/beans/factory/annotation/Autowired")) {
								inject = true;
								break;
							}
						}
					}
					declareClass = field.getDeclaringClass();
				} else {
					IClass may = cg.getClassHierarchy().lookupClass(fieldType);
					if (may != null) {
						declareClass = may;
					}
					fieldType = inst.getDeclaredTarget().getDeclaringClass();
//					else {
//						fieldType = declareClass.getReference();
//					}

				}
				RepoElement ele = new RepoElement(declareClass, fieldType, fieldName, inject, bb);
				return ele;
			} else if (base == 1 && (inst instanceof SSAInvokeInstruction)) {
				// for lin-cms
				RepoElement ele = new RepoElement(bb.getMethod().getDeclaringClass(),
						inst.getDeclaredTarget().getDeclaringClass(), bb.getMethod().getName().toString(), false, bb);
				return ele;
			}
		}
		return null;
	}

	/**
	 * c1 := (cast)c2 </br>
	 * is tr2 a subtype of tr1?
	 */
	public static boolean canAssignableFrom(TypeReference tr1, TypeReference tr2, IClassHierarchy cha) {
		if (tr1.getName().equals(tr2.getName())) {
			return true;
		} else {
			IClass c1 = cha.lookupClass(tr1);
			IClass c2 = cha.lookupClass(tr2);
			if (c1 != null && c2 != null) {
				if (cha.isAssignableFrom(c1, c2)) {
					return true;
				}
			} else {
				if (c2 != null) {
					// tr2 is app class but tr1 is framework
					if (c2 instanceof BytecodeClass) {
						BytecodeClass<?> bc = (BytecodeClass<?>) c2;
						Collection<String> interfs = bc.getAllInterfaceNames();
						String name1 = tr1.getName().toString();
						if (interfs.contains(name1))
							return true;
						if (bc.getAllSuperClasses().contains(name1))
							return true;

					}
				}
			}
		}
		return false;
	}

}
