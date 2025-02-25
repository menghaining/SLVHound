package SLVHound.checker.core.infer.dataflow;

import java.util.HashSet;
import java.util.Set;

import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IField;
import com.ibm.wala.dataflow.IFDS.TabulationDomain;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAInvokeInstruction;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.types.FieldReference;
import com.ibm.wala.types.TypeReference;

public class Util {
	public static int genSourceForRetValue(
			TabulationDomain<TaintDomainElement, BasicBlockInContext<IExplodedBasicBlock>> domain,
			BasicBlockInContext<IExplodedBasicBlock> callsite, String type) {
		SSAInstruction inst = callsite.getLastInstruction();
		assert inst != null && inst instanceof SSAInvokeInstruction;
		int vn = 0;
		if (inst.hasDef()) {
			vn = inst.getDef();
		} else {
			String calleeName = ((SSAInvokeInstruction) inst).getDeclaredTarget().getName().toString();
			assert calleeName.equals("<init>");
			assert inst.getNumberOfUses() >= 1;
			vn = inst.getUse(0);
		}
		Set<BasicBlockInContext<IExplodedBasicBlock>> rs = new HashSet<BasicBlockInContext<IExplodedBasicBlock>>();
		rs.add(callsite);

		AccessPath ap = new AccessPath(vn, null, callsite.getNode());
		TaintDomainElement de = new TaintDomainElement(callsite.getNode(), inst, ap,
				new SourceContext(callsite, ap, type));
		return domain.add(de);
	}
	
	public static boolean isCommonField(IClassHierarchy cha, FieldReference fr1, FieldReference fr2) {
		if (!fr1.getName().equals(fr2.getName()))
			return false;
		IField field1 = cha.resolveField(fr1);
		IField field2 = cha.resolveField(fr2);
		if (field1 != null && field1.isPrivate() && !fr1.equals(fr2))
			return false;
		if (field2 != null && field2.isPrivate() && !fr2.equals(fr1))
			return false;
		TypeReference typeRef1 = fr1.getDeclaringClass();
		IClass clazz1 = cha.lookupClass(typeRef1);
		TypeReference typeRef2 = fr2.getDeclaringClass();
		IClass clazz2 = cha.lookupClass(typeRef2);
		if (clazz1 == null || clazz2 == null) {
			return false;
		}
		return cha.isAssignableFrom(clazz1, clazz2) || cha.isAssignableFrom(clazz2, clazz1);
	}
}
