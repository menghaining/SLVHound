package SLVHound.checker.core.db;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentType;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.ibm.wala.classLoader.BytecodeClass;
import com.ibm.wala.classLoader.CallSiteReference;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.ssa.SSAAbstractInvokeInstruction;
import com.ibm.wala.ssa.SSACheckCastInstruction;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAInvokeInstruction;
import com.ibm.wala.ssa.SSAPhiInstruction;
import com.ibm.wala.ssa.SSAReturnInstruction;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.types.MethodReference;
import com.ibm.wala.types.TypeReference;

public class DBHelper {
	static DBHelper instance = null;
	static CallGraph cg = null;

	public static void init(String app, CallGraph cg2) {
		instance = new DBHelper(app);
		cg = cg2;
	}

	public static DBHelper instance() {
		return instance;
	}

	public DBHelper(String app) {
		readMybatisXMLs(app);
	}

	public boolean isAction2DBAgentInvoke(CGNode node, SSAInvokeInstruction invoke, String action) {
		IClassHierarchy cha = cg.getClassHierarchy();
		// spring db
		IClass targetDecClass = cha.lookupClass(invoke.getDeclaredTarget().getDeclaringClass());
		if (targetDecClass != null && (targetDecClass instanceof BytecodeClass)
				&& targetDecClass.getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
			String methodLowername = invoke.getDeclaredTarget().getName().toString().toLowerCase();
			for (String interf : ((BytecodeClass<?>) targetDecClass).getAllInterfaceNames()) {
				if (isSpringAction(interf, methodLowername, action))
					return true;
			}
			// redis db implemented by spring
			String superClassName = ((BytecodeClass<?>) targetDecClass).getSuperName().toString();
			if (isSpringAction(superClassName, methodLowername, action))
				return true;
		}
		// redis db
		if (isRedisAction(invoke.getDeclaredTarget(), action))
			return true;

		// Mybatis-xml and extends interface
		if (isMybatisAction(invoke, targetDecClass, action))
			return true;

		if (isMongoDBAction(invoke.getDeclaredTarget(), action))
			return true;
//		// java ee api
//		if (isJavaEEAction(node, invoke, action, cg))
//			return true;

		return false;
	}

	public boolean isDBMethod(SSAInvokeInstruction invoke, IClassHierarchy cha) {
		// spring db
		IClass targetDecClass = cha.lookupClass(invoke.getDeclaredTarget().getDeclaringClass());
		if (targetDecClass != null && (targetDecClass instanceof BytecodeClass)
				&& targetDecClass.getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
			for (String interf : ((BytecodeClass<?>) targetDecClass).getAllInterfaceNames()) {
				if (isSpringRepositoryClass(interf))
					return true;
			}
			// redis db implemented by spring
			String superClassName = ((BytecodeClass<?>) targetDecClass).getSuperName().toString();
			if (isSpringRepositoryClass(superClassName))
				return true;
		}

		// redis db
		String targetSig = invoke.getDeclaredTarget().getSignature();
		if (isRedisDBClass(targetSig))
			return true;

		// Mybatis-xml and extends interface
		String decalreClass = invoke.getDeclaredTarget().getDeclaringClass().getName().toString();
		String classname = decalreClass.replace('/', '.').substring(1);
		if (isMybatisClass(classname))
			return true;
		if (targetDecClass != null && (targetDecClass instanceof BytecodeClass)
				&& targetDecClass.getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
			for (String interf : ((BytecodeClass<?>) targetDecClass).getAllInterfaceNames()) {
				// mybatis mapper as interface may extends other interface
				if (isMybatisClass(interf)) {
					return true;
				}
			}
			for (String sp : ((BytecodeClass<?>) targetDecClass).getAllSuperClasses()) {
				if (isMybatisClass(sp)) {
					return true;
				}
			}
		}

		return false;
	}

	/* --------------------JavaEE API DB---------------------------- */

	public boolean isJavaEEAction(CGNode node, SSAInvokeInstruction invoke, String action, HashSet<CGNode> visited) {
		// 1. recognize EntityManager
		if (isJavaEEAPIEMClass(invoke.getDeclaredTarget().getSignature())) {
			if (action.equals("get")) {
				if (isJavaEEAPIEMGet(invoke.getDeclaredTarget().getSignature())) {
					return true;
				} else if (isJavaEEAPIQueryCreate(invoke.getDeclaredTarget().getSignature())) {
					// em = create(xx);
					// find em.action?
					int def = invoke.getDef();
					Iterator<SSAInstruction> it = node.getDU().getUses(def);
					while (it.hasNext()) {
						SSAInstruction inst = it.next();
						if (inst instanceof SSAInvokeInstruction) {
							if (isJavaEEAPIQueryGet(((SSAInvokeInstruction) inst).getDeclaredTarget().getSignature()))
								return true;
						} else if (inst instanceof SSAReturnInstruction) {
							for (CGNode v : visited) {
								Iterator<CallSiteReference> csit = v.iterateCallSites();
								while (csit.hasNext()) {
									CallSiteReference cs = csit.next();
									if (cs.getDeclaredTarget().getSignature().equals(node.getMethod().getSignature())) {
										SSAAbstractInvokeInstruction[] iivs = v.getIR().getCalls(cs);
										// for each callsite invoke Instruction
										for (SSAAbstractInvokeInstruction iv : iivs) {
											if (iv.getDef() != -1) {
												HashSet<SSAInvokeInstruction> candidates = new HashSet<SSAInvokeInstruction>();
												getAllInvokeInsts(iv.getDef(), v, candidates);
												for (SSAInvokeInstruction candidate : candidates) {
													if (isJavaEEAPIQueryGet(
															candidate.getDeclaredTarget().getSignature())) {
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
			}
		}
		return false;
	}

	private void getAllInvokeInsts(int def, CGNode v, HashSet<SSAInvokeInstruction> ret) {
		Iterator<SSAInstruction> it = v.getDU().getUses(def);
		while (it.hasNext()) {
			SSAInstruction iinst = it.next();
			if (iinst instanceof SSAPhiInstruction || iinst instanceof SSACheckCastInstruction) {
				if (iinst.getDef() != -1)
					getAllInvokeInsts(iinst.getDef(), v, ret);
			} else if (iinst instanceof SSAInvokeInstruction) {
				ret.add((SSAInvokeInstruction) iinst);
			}
		}
	}

	public boolean isJavaEEAPIEMClass(String signature) {
		if (signature.startsWith("jakarta.persistence.EntityManager"))
			return true;
		return false;
	}

	private boolean isJavaEEAPIEMGet(String signature) {
		if (signature.startsWith("jakarta.persistence.EntityManager.find"))
			return true;
		return false;
	}

	private boolean isJavaEEAPIQueryCreate(String signature) {
		if (signature.startsWith("jakarta.persistence.EntityManager.create"))
			return true;
		return false;
	}

	private boolean isJavaEEAPIQueryGet(String signature) {
		if (signature.startsWith("jakarta.persistence.TypedQuery.getSingleResult")
				|| signature.startsWith("jakarta.persistence.TypedQuery.getResult")
				|| signature.startsWith("jakarta.persistence.Query.getSingleResult")
				|| signature.startsWith("jakarta.persistence.Query.getResult")
				|| signature.startsWith("jakarta.persistence.Query.getFirstResult"))
			return true;
		return false;
	}

	private boolean isJavaEEAPIHas(String signature) {
//		if(signature.startsWith(""))
//			return true;
		return false;
	}

	private boolean isJavaEEAPISave(String signature) {
		if (signature.startsWith("jakarta.persistence.Query.executeUpdate")
				|| signature.startsWith("jakarta.persistence.EntityManager.merge")
				|| signature.startsWith("jakarta.persistence.EntityManager.persist")
				|| signature.startsWith("jakarta.persistence.EntityManager.remove")
				|| signature.startsWith("jakarta.persistence.EntityManager.detach"))
			return true;
		return false;
	}

	/* --------------------spring DB---------------------------- */
	public boolean isSpringAction(String interf, String methodLowername, String action) {
		switch (action) {
		case "save":
			if (isSpringDBSave(interf, methodLowername))
				return true;
			break;
		case "get":
			if (isSpringDBGet(interf, methodLowername))
				return true;
			break;
		case "has":
			if (isSpringDBHas(interf, methodLowername))
				return true;
			break;
		}
		return false;
	}

	public boolean isSpringRepositoryClass(String interf) {
		if (interf.equals("Lorg/springframework/data/jpa/repository/JpaRepository"))
			return true;
		// redis db implemented in spring
		if (interf.equals("Lorg/springframework/data/redis/core/RedisTemplate"))
			return true;
		return false;
	}

	public boolean isSpringDBGet(String interf, String methodLowername) {
		if (isSpringRepositoryClass(interf))
			if (methodLowername.startsWith("findby") || methodLowername.startsWith("readby")
					|| methodLowername.startsWith("get")) {
				return true;
			}
		return false;
	}

	public boolean isSpringDBSave(String interf, String methodLowername) {
		if (isSpringRepositoryClass(interf))
			if (methodLowername.startsWith("save") || methodLowername.startsWith("insert")
					|| methodLowername.startsWith("create")) {
				return true;
			}
		return false;
	}

	private boolean isSpringDBHas(String interf, String methodLowername) {
		if (isSpringRepositoryClass(interf))
			if (methodLowername.startsWith("exists") || methodLowername.startsWith("has")) {
				return true;
			}
		return false;
	}

	/* --------------------JdbcTemplate---------------------------- */
	public boolean isJdbcTemplate(CGNode node, SSAInvokeInstruction invoke, String action) {
		String sig = invoke.getDeclaredTarget().getSignature();
		if (!isJdbcTemplateClass(sig))
			return false;
		int vn = invoke.getUse(1);
		System.out.println("[jdbc]" + invoke + ":" + vn);
		if (vn == -1)
			return false;
		String sql = node.getIR().getSymbolTable().getStringValue(vn);
		if (sql == null)
			return false;
		System.out.println("[SQL]" + sql);
		switch (action) {
		case "save":
			if (isJdbcTemplateSave(sig, sql))
				return true;
			break;
		case "get":
			if (isJdbcTemplateGet(sig, sql))
				return true;
			break;
		case "has":
			if (isJdbcTemplateHas(sig, sql))
				return true;
		case "new":
			if (isJdbcTemplateNew(sig, sql))
				return true;

		}
		return false;
	}

	public SQLQuery parseSQL(CGNode node, SSAInvokeInstruction invoke) {
		System.out.println("[parsing pure SQL]" + invoke + "\n\t" + node.getMethod());
		if (invoke.getNumberOfUses() < 2)
			return null;
		int vn = invoke.getUse(1);
		if (vn == -1)
			return null;
		if (node.getIR().getSymbolTable().isStringConstant(vn)) {
			String sql = node.getIR().getSymbolTable().getStringValue(vn);
			if (sql == null)
				return null;
			return SQLParser.parseSql(sql);
		}
		return null;
	}

	public boolean isJdbcTemplateClass(String sig) {
		if (sig.startsWith("org.springframework.jdbc.core.JdbcTemplate"))
			return true;
		return false;
	}

	private boolean isJdbcTemplateNew(String sig, String sql) {
		if (sig.startsWith("org.springframework.jdbc.core.JdbcTemplate.update")) {
			if (sql.toLowerCase().startsWith("insert"))
				return true;
		}
		return false;
	}

	// only modify
	private boolean isJdbcTemplateSave(String sig, String sql) {
		if (sig.startsWith("org.springframework.jdbc.core.JdbcTemplate.update")) {
			if (!sql.toLowerCase().startsWith("delete") && !sql.toLowerCase().startsWith("insert"))
				return true;
		}
		return false;
	}

	private boolean isJdbcTemplateGet(String sig, String sql) {
		if (sig.startsWith("org.springframework.jdbc.core.JdbcTemplate.query")) {
			return true;
		}
		return false;
	}

	private boolean isJdbcTemplateHas(String sig, String sql) {
		// TODO Auto-generated method stub
		return false;
	}

	/* --------------------MongoDB---------------------------- */
	private boolean isMongoDBAction(MethodReference declaredTarget, String action) {
		switch (action) {
		case "save":
			if (isMongoDBsave(declaredTarget))
				return true;
			break;
		case "get":
			if (isMongoDBGet(declaredTarget))
				return true;
			break;
		case "has":
			if (isMongoDBHas(declaredTarget))
				return true;

		}
		return false;
	}

	public boolean isMongoDBClass(String targetSig) {
		if (targetSig.startsWith("com.mongodb.DBCollection")) {
			return true;
		}
		return false;
	}

	private boolean isMongoDBGet(MethodReference declaredTarget) {
		String targetSig = declaredTarget.getSignature();
		if (isMongoDBClass(targetSig)) {
			String mtdname = declaredTarget.getSelector().getName().toString();
			if (mtdname.startsWith("find")) {
				return true;
			}
		}
		return false;
	}

	private boolean isMongoDBsave(MethodReference declaredTarget) {
		// TODO Auto-generated method stub
		return false;
	}

	private boolean isMongoDBHas(MethodReference declaredTarget) {
		// TODO Auto-generated method stub
		return false;
	}

	private boolean isRedisAction(MethodReference declaredTarget, String action) {
		switch (action) {
		case "save":
			if (isRedisDBsave(declaredTarget))
				return true;
			break;
		case "get":
			if (isRedisDBGet(declaredTarget))
				return true;
			break;
		case "has":
			if (isRedisDBHas(declaredTarget))
				return true;

		}
		return false;
	}

	public boolean isRedisDBClass(String targetSig) {
		if (targetSig.startsWith("org.springframework.data.redis.core.ValueOperations")
				|| targetSig.startsWith("org.springframework.data.redis.core.HashOperations")
				|| targetSig.startsWith("org.springframework.data.redis.core.RedisTemplate")
				|| targetSig.startsWith("org.springframework.data.redis.core.StringRedisTemplate")) {
			return true;
		}
		return false;
	}

	public boolean isRedisDBGet(MethodReference declaredTarget) {
		String targetSig = declaredTarget.getSignature();
		if (isRedisDBClass(targetSig)) {
			String mtdname = declaredTarget.getSelector().getName().toString();
			if (mtdname.equals("get")) {
				return true;
			}
		}
		return false;
	}

	public boolean isRedisDBsave(MethodReference declaredTarget) {
		String targetSig = declaredTarget.getSignature();
		if (isRedisDBClass(targetSig)) {
			String mtdname = declaredTarget.getSelector().getName().toString();
			if (mtdname.equals("set") || mtdname.equals("put")) {
				return true;
			}
		}
		return false;
	}

	private boolean isRedisDBHas(MethodReference declaredTarget) {
		String targetSig = declaredTarget.getSignature();
		if (isRedisDBClass(targetSig)) {
			String mtdname = declaredTarget.getSelector().getName().toString();
			if (mtdname.toLowerCase().startsWith("has")) {
				return true;
			}
		}
		return false;
	}

	/* --------------------Mybatis DB---------------------------- */
	private boolean isMybatisAction(SSAInvokeInstruction invoke, IClass targetDecClass, String action) {
		switch (action) {
		case "save":
			if (isMybatisDBsave(invoke))
				return true;
			break;
		case "get":
			if (isMybatisDBGet(invoke, targetDecClass))
				return true;
			break;
		case "has":
			if (isMybatisDBHas(invoke))
				return true;
			break;

		}
		return false;
	}

	private boolean isMybatisClass(String classname) {
		if (mybatis_class2OP2Name.containsKey(classname))
			return true;
		if (classname.equals("Lcom/baomidou/mybatisplus/core/mapper/BaseMapper"))
			return true;
		if (classname.equals("Ltk/mybatis/mapper/common/Mapper"))
			return true;
		if (classname.equals("Lcom/baomidou/mybatisplus/extension/service/impl/ServiceImpl"))
			return true;
		if (classname.equals("Lcom/baomidou/mybatisplus/extension/service/IService"))
			return true;
		return false;
	}

	private boolean isMybatisDBsave(SSAInvokeInstruction invoke) {
		String decalreClass = invoke.getDeclaredTarget().getDeclaringClass().getName().toString();
		String classname = decalreClass.replace('/', '.').substring(1);
		String mn = invoke.getDeclaredTarget().getName().toString();
		if (isMybatisClass(classname)) {
			HashSet<String> mtdNamesU = mybatis_class2OP2Name.get(classname).get("update");
			if (mtdNamesU != null) {
				if (mtdNamesU.contains(mn)) {
					return true;
				}
			}
			HashSet<String> mtdNamesI = mybatis_class2OP2Name.get(classname).get("insert");
			if (mtdNamesI != null) {
				if (mtdNamesI.contains(mn)) {
					return true;
				}
			}
		}
		// extends com.baomidou.mybatisplus.core.mapper.BaseMapper
		IClass targetDecClass = cg.getClassHierarchy().lookupClass(invoke.getDeclaredTarget().getDeclaringClass());
		if (targetDecClass != null && (targetDecClass instanceof BytecodeClass)
				&& targetDecClass.getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
			for (String interf : ((BytecodeClass<?>) targetDecClass).getAllInterfaceNames()) {
				// mybatis mapper as interface may extends other interface
				if (isMybatisClass(interf)) {
					if (mn.equals("insert") || mn.startsWith("update"))
						return true;
				}
			}
		}

		return false;
	}

	private boolean isMybatisDBGet(SSAInvokeInstruction invoke, IClass targetDecClass) {
		// 1. XML
		String decalreClass = invoke.getDeclaredTarget().getDeclaringClass().getName().toString();
		String classname = decalreClass.replace('/', '.').substring(1);
		if (isMybatisClass(classname)) {
			HashSet<String> mtdNames = mybatis_class2OP2Name.get(classname).get("select");
			if (mtdNames != null) {
				String mn = invoke.getDeclaredTarget().getName().toString();
				if (mtdNames.contains(mn)) {
					return true;
				}
			}
		}
		// 2. extends interface
		if (targetDecClass != null && (targetDecClass instanceof BytecodeClass)
				&& targetDecClass.getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
			String methodLowername = invoke.getDeclaredTarget().getName().toString().toLowerCase();
			for (String interf : ((BytecodeClass<?>) targetDecClass).getAllInterfaceNames()) {
				// mybatis mapper as interface may extends other interface
				if (isMybatisClass(interf)) {
					if (methodLowername.startsWith("select") || methodLowername.startsWith("get"))
						return true;
				}
			}
			for (String sp : ((BytecodeClass<?>) targetDecClass).getAllSuperClasses()) {
				if (isMybatisClass(sp)) {
					if (methodLowername.startsWith("select") || methodLowername.startsWith("get"))
						return true;
				}
			}
		}

		return false;
	}

	private boolean isMybatisDBHas(SSAInvokeInstruction invoke) {
		String decalreClass = invoke.getDeclaredTarget().getDeclaringClass().getName().toString();
		String classname = decalreClass.replace('/', '.').substring(1);
		if (isMybatisClass(classname)) {
			HashSet<String> mtdNames = mybatis_class2OP2Name.get(classname).get("select");
			if (mtdNames != null) {
				return true;
			}
		}
		return false;
	}

	public HashMap<String, HashMap<String, HashSet<String>>> mybatis_class2OP2Name = new HashMap<>();

	private void readMybatisXMLs(String app) {
		Set<String> XMLFileList = new HashSet<>();
		iterateXMLFiles(new File(app), XMLFileList);
		for (String path : XMLFileList) {
			File file = new File(path);
			SAXReader reader = new SAXReader();
			reader.setValidation(false);
			reader.setEntityResolver(new EntityResolver() {
				@Override
				public InputSource resolveEntity(String publicId, String systemId) throws SAXException, IOException {
					return new InputSource(new ByteArrayInputStream("".getBytes()));
				}
			});
			try {
				Document document = reader.read(file);
				/* exclude database configure */
				DocumentType docType = document.getDocType();
//				System.out.println();
				if (docType != null) {
					docType.getElementName();
					if (docType.getSystemID().toLowerCase().contains("mybatis")) {
						String fullQualifiedClassName = null;
						Element root = document.getRootElement();
						for (Object attr : root.attributes()) {
							if (attr instanceof Attribute) {
								if (((Attribute) attr).getName().equals("namespace")) {
									fullQualifiedClassName = ((Attribute) attr).getValue();
									break;
								}
							}
						}
						// operations and names
						HashMap<String, HashSet<String>> op2names = new HashMap<>();
						if (fullQualifiedClassName != null)
							for (Object child0 : root.elements()) {
								if (child0 instanceof Element) {
									Element child = (Element) child0;
									String op = child.getName();
									for (Object cattr : child.attributes()) {
										if (cattr instanceof Attribute) {
											if (((Attribute) cattr).getName().equals("id")) {
												String name = ((Attribute) cattr).getValue();
												if (!op2names.containsKey(op))
													op2names.put(op, new HashSet<>());
												op2names.get(op).add(name);
											}
										}
									}
								}
							}
						if (!op2names.isEmpty()) {
							if (!mybatis_class2OP2Name.containsKey(fullQualifiedClassName))
								mybatis_class2OP2Name.put(fullQualifiedClassName, op2names);
						}
					}
				}
			} catch (DocumentException e) {
				System.err.println("[error][DocumentException]" + e.getMessage() + " when parse " + file);
			}
		}

	}

	private void iterateXMLFiles(File file, Set<String> XMLFileList) {
		File[] fs = file.listFiles();
		for (File f : fs) {
			if (f.isDirectory())
				iterateXMLFiles(f, XMLFileList);
			if (f.isFile()) {
				if (f.getName().endsWith(".xml")) {
					if (!XMLFileList.contains(f.getPath()))
						XMLFileList.add(f.getPath());
				}
			}
		}
	}

	/* --------------------parse DB statement---------------------------- */
	public List<String> parseDBstmt2findAttrs(String input) {
		List<String> ret = new ArrayList<>();
		// 1. spring-jpa
		List<String> substrings = new ArrayList<>();
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < input.length(); i++) {
			char c = input.charAt(i);
			if (Character.isUpperCase(c)) {
				if (sb.length() > 0) {
					substrings.add(sb.toString());
					sb.setLength(0);
				}
			}
			sb.append(c);
		}

		if (sb.length() > 0) {
			substrings.add(sb.toString());
		}

		boolean start = false;
		for (String str : substrings) {
			if (str.equals("By") || str.equals("Is") || str.equals("In")) {
				start = true;
				continue;
			}
			if (!str.equals("select") && !str.equals("find") && !str.equals("get") && !str.equals("By")
					&& !str.equals("And") && !str.equals("In") && !str.equals("Or") && !str.equals("Not")
					&& !str.equals("Is") && !str.equals("True") && !str.equals("False"))
				if (start)
					ret.add(str.toLowerCase());
		}

		return ret;
	}

	public boolean canCastSame(TypeReference tr1, TypeReference tr2, IClassHierarchy cha) {
		if (tr1 == null || tr2 == null)
			return false;
		String name1 = tr1.getName().toString();
		String name2 = tr2.getName().toString();

		if (name1.equals(name2))
			return true;

		if (isSub(tr1, tr2, cha) || isSub(tr2, tr1, cha))
			return true;

		if (isRedisDBClass(name2.substring(1).replace('/', '.'))) {
			IClass c1 = cha.lookupClass(tr1);
			if (c1 != null && c1 instanceof BytecodeClass<?>) {
				for (String interf : ((BytecodeClass<?>) c1).getAllInterfaceNames()) {
					if (isRedisDBClass(interf.substring(1).replace('/', '.'))) {
						return true;
					}
				}
				for (String sup : ((BytecodeClass<?>) c1).getAllSuperClasses()) {
					if (isRedisDBClass(sup.substring(1).replace('/', '.'))) {
						return true;
					}
				}
			}
		}

		if (isRedisDBClass(name1.substring(1).replace('/', '.'))) {
			IClass c2 = cha.lookupClass(tr2);
			if (c2 != null && c2 instanceof BytecodeClass<?>) {
				for (String interf : ((BytecodeClass<?>) c2).getAllInterfaceNames()) {
					if (isRedisDBClass(interf.substring(1).replace('/', '.'))) {
						return true;
					}
				}
				for (String sup : ((BytecodeClass<?>) c2).getAllSuperClasses()) {
					if (isRedisDBClass(sup.substring(1).replace('/', '.'))) {
						return true;
					}
				}
			}
		}

		return false;
	}

	private boolean isSub(TypeReference tr1, TypeReference tr2, IClassHierarchy cha) {
		IClass c1 = cha.lookupClass(tr1);
		if (c1 != null && c1 instanceof BytecodeClass<?>) {
			for (String interf : ((BytecodeClass<?>) c1).getAllInterfaceNames()) {
				if (interf.equals(tr2.getName().toString())) {
					return true;
				}
			}
			for (String sup : ((BytecodeClass<?>) c1).getAllSuperClasses()) {
				if (sup.equals(tr2.getName().toString())) {
					return true;
				}
			}
		}
		return false;
	}

	public boolean updateExist(String signature) {
		if (signature.contains("updateByPrimaryKeySelective"))
			return true;
		return false;
	}

}
