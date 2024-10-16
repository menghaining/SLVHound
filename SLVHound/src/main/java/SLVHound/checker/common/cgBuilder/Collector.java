package SLVHound.checker.common.cgBuilder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.dom4j.Element;

import com.ibm.wala.classLoader.BytecodeClass;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IField;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.classLoader.ShrikeClass;
import com.ibm.wala.ipa.cha.ClassHierarchy;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.shrikeCT.AnnotationsReader.ConstantElementValue;
import com.ibm.wala.shrikeCT.AnnotationsReader.ElementValue;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.types.TypeName;
import com.ibm.wala.types.TypeReference;
import com.ibm.wala.types.annotations.Annotation;

public class Collector {
	public static Set<IMethod> collectEntryMethod(ClassHierarchy cha, Set<String> xMLFileList) {
		Set<IMethod> ret = new HashSet<>();

		Set<IConfig> configSpecificationEP = FrameworkConfigReader.instance().getEpSpecification();
		Map<IClass, Set<Element>> class2XMLElement = XMLConfigHandler.instance(xMLFileList, cha)
				.getClassConfigurations();

		cha.getLoader(ClassLoaderReference.Application).iterateAllClasses().forEachRemaining(clazz -> {
			for (IMethod m : clazz.getDeclaredMethods()) {
				boolean find = false;
				/*
				 * 1. deal with annotations
				 */
				if (m.getAnnotations() != null) {
					for (IConfig conf : configSpecificationEP) {
						if (((EntryConfig) conf).getType().equals(FrameworkConfigType.anno)) {
							String mtdconfig = ((EntryConfig) conf).getMethodConfig();
							for (Annotation anno : m.getAnnotations()) {
								TypeName name = anno.getType().getName();
								if (name.toString().equals(FrameworkUtil.makeType2(mtdconfig))) {
									find = true;
									break;
								}
							}
							if (find)
								break;
						}
					}
					if (find) {
						ret.add(m);
						continue;
					}
				}
				/*
				 * 2. deal with XML
				 */
				if (class2XMLElement.containsKey(clazz)) {
					for (IConfig conf : configSpecificationEP) {
						if (((EntryConfig) conf).getType().equals(FrameworkConfigType.xml)) {
							String mtdconfig = ((EntryConfig) conf).getMethodConfig();
							for (Element ele : class2XMLElement.get(clazz)) {
								String rootPath = XMLConfigHandler.buildPath(ele);
								if (mtdconfig.startsWith(rootPath)) {
									String sufix = mtdconfig.substring(rootPath.length());
									Element hasMethod = XMLConfigHandler.hasValue(sufix, ele, m.getName().toString());
									if (hasMethod != null) {
										ret.add(m);
										find = true;
										break;
									}
								}
							}
						}
						if (find)
							break;
					}
					if (find)
						continue;
				}
				/*
				 * 3. deal with code configure: heuristic to check implement class and method
				 */
				IClass declareClass = m.getDeclaringClass();
				String name = m.getName().toString();
				for (String interf : ((BytecodeClass<?>) declareClass).getAllInterfaceNames()) {
					// spring
					if (interf.equals("Lorg/springframework/web/servlet/HandlerInterceptor")
							|| interf.equals("Lorg/springframework/web/servlet/handler/HandlerInterceptorAdapter")) {
						if (name.toLowerCase().equals("prehandle")) {
							ret.add(m);
							find = true;
							break;
						}
					}
					if (interf.equals("Lorg/springframework/web/socket/server/HandshakeInterceptor"))
						if (name.equals("beforeHandshake")) {
							ret.add(m);
							find = true;
							break;
						}
					// javaee
					if (interf.equals("Ljavax/servlet/Filter")) {
						if (name.toLowerCase().equals("dofilter")) {
							ret.add(m);
							find = true;
							break;
						}
					}
				}
				for (String sp : ((BytecodeClass<?>) declareClass).getAllSuperClasses()) {
					if (sp.equals("Lorg/springframework/web/filter/OncePerRequestFilter")) {
						if (name.toLowerCase().equals("dofilterinternal")) {
							ret.add(m);
							find = true;
							break;
						}
					}
					if (sp.equals("Lorg/springframework/security/web/authentication/www/BasicAuthenticationFilter")) {
						if (name.toLowerCase().equals("dofilterinternal")) {
							ret.add(m);
							find = true;
							break;
						}
					}
					if (sp.equals("Lcom/opensymphony/xwork2/ActionSupport") && !(m.isClinit() || m.isInit())
							&& !m.isAbstract()) {
						ret.add(m);
						find = true;
						break;
					}
				}
				if (find)
					continue;
				/*
				 * 4. apache shiro login special class
				 **/
				for (String superclazz : ((BytecodeClass<?>) declareClass).getAllSuperClasses()) {
					if (superclazz.equals("Lorg/apache/shiro/realm/AuthorizingRealm")
							|| superclazz.equals("Lorg/apache/shiro/realm/AuthenticatingRealm")) {
						if (name.equals("doGetAuthenticationInfo")) {
							ret.add(m);
							find = true;
							break;
						}
					}
				}
				if (find)
					continue;
				/*
				 * 5. spring security login special class
				 **/
				for (String interf : ((BytecodeClass<?>) declareClass).getAllInterfaceNames()) {
					if (interf.equals("Lorg/springframework/security/authentication/AuthenticationProvider")) {
						if (name.equals("authenticate")) {
							ret.add(m);
							find = true;
							break;
						}
					} else if (interf.equals("Lorg/springframework/security/core/userdetails/UserDetailsService")) {
						if (name.equals("loadUserByUsername")) {
							ret.add(m);
							find = true;
							break;
						}
					}
				}
			}

		});

		return ret;
	}

	public static Map<IField, TypeReference> collectField(IClassHierarchy cha, Set<String> xMLFileList) {
		Map<IField, TypeReference> field2Target = new HashMap<>();

		Set<IConfig> configSpecification = FrameworkConfigReader.instance().getFieldSpecification();
		Map<IClass, Set<Element>> class2XMLElement = XMLConfigHandler.instance(xMLFileList, cha)
				.getClassConfigurations();

		cha.getLoader(ClassLoaderReference.Application).iterateAllClasses().forEachRemaining(clazz -> {
			// heuristic-240315: iterate all init methods to find @Autowired
			HashSet<TypeReference> mtdInject = new HashSet<>();
			for (IMethod mtd : ((ShrikeClass) clazz).getInitMethod()) {
				if (mtd.getName().toString().equals("<init>")) {
					String mtdAnno1 = "Lorg/springframework/beans/factory/annotation/Autowired";
					String mtdAnno2 = "Lcom/google/inject/Inject";
					if (mtd.getAnnotations() != null) {
						for (Annotation anno : mtd.getAnnotations()) {
							TypeName name = anno.getType().getName();
							if (name.toString().equals(mtdAnno1) || name.toString().equals(mtdAnno2)) {
								for (int i = 1; i < mtd.getNumberOfParameters(); i++) {
									TypeReference type = mtd.getParameterType(i);
									mtdInject.add(type);
								}
							}
						}
					}
				}
			}

			for (IField f : clazz.getDeclaredInstanceFields()) {
				// heuristic-240315: iterate all init methods to find @Autowired
				if (mtdInject.contains(f.getFieldTypeReference())) {
					if (!field2Target.containsKey(f)) {
						TypeReference target = f.getReference().getFieldType();
						IClass targetClazz = cha.lookupClass(target);
						if (targetClazz != null) {
							if (targetClazz.isAbstract()) {
								Set<IClass> impls = cha.getImplementors(target);
								for (IClass tar : impls) {
									field2Target.put(f, tar.getReference());
									break;
								}
							} else {
								field2Target.put(f, target);
							}
						}

					}
				}
				/*
				 * 1. deal with annotations
				 */
				if (f.getAnnotations() != null) {
					Annotation f_anno = null;
					Annotation p_anno = null;
					for (IConfig conf : configSpecification) {
						if (((FieldConfig) conf).getType().equals(FrameworkConfigType.anno)) {
							List<String> configs = ((FieldConfig) conf).getConfigs();
							assert configs.size() == 2;
							String injectConfig = configs.get(0);
							String points2Config = configs.get(1);
							for (Annotation anno : f.getAnnotations()) {
								TypeName name = anno.getType().getName();
								if (name.toString().equals(FrameworkUtil.makeType2(injectConfig)))
									f_anno = anno;
								if ((points2Config.length() != 0)
										&& name.toString().equals(FrameworkUtil.makeType2(points2Config)))
									p_anno = anno;
							}
						}
					}
					if (f_anno != null) {
						if (!field2Target.containsKey(f)) {
							if (f.getReference().getFieldType().isPrimitiveType())
								field2Target.put(f, f.getReference().getFieldType());
							else {
								IClass target = findFieldTarget(f, p_anno, cha, class2XMLElement);
								if (target == null)
									field2Target.put(f, null);
								else
									field2Target.put(f, target.getReference());
							}
						}
					}
				}

				/*
				 * 2. deal with XML
				 */
				if (class2XMLElement.containsKey(clazz)) {
					for (IConfig conf : configSpecification) {
						if (((FieldConfig) conf).getType().equals(FrameworkConfigType.xml)) {
							List<String> configs = ((FieldConfig) conf).getConfigs();
							assert configs.size() == 2;
							String injectConfig = configs.get(0);
							String points2Config = configs.get(1);

							for (Element ele : class2XMLElement.get(clazz)) {
								String rootPath = XMLConfigHandler.buildPath(ele);
								if (injectConfig.startsWith(rootPath)) {
									String sufix = injectConfig.substring(rootPath.length());
									Element hasField = XMLConfigHandler.hasValue(sufix, ele, f.getName().toString());

									if (hasField != null) {
										if (!field2Target.containsKey(f)) {
											if (f.getReference().getFieldType().isPrimitiveType()) {
												field2Target.put(f, f.getReference().getFieldType());
											} else {
												IClass target = null;
												if (points2Config.length() != 0) {
													String fieldrootPath = XMLConfigHandler.buildPath(hasField);
													if (points2Config.startsWith(rootPath)) {
														if (points2Config.startsWith(fieldrootPath)) {
															String points2sufix = points2Config
																	.substring(fieldrootPath.length());
															String points2val = XMLConfigHandler
																	.findPoints2Value(points2sufix, hasField);
															if (points2val != null && points2val.length() != 0) {
																target = findFieldTarget(f, points2val, cha,
																		class2XMLElement);
															}
														}
													}
												}
												if (target == null)
													field2Target.put(f, null);
												else
													field2Target.put(f, target.getReference());
											}
										}
										break;
									}
								}
							}
						}
					}
				}
			}
		});

		return field2Target;
	}

	/**
	 * 
	 * Return the configured field target as flow rules sequence among all sub-class
	 * or implement class of field declared type:</br>
	 * 1. field-config-value v.s. class configuration value;</br>
	 * 2. field-config-value v.s. class declared name;</br>
	 * 3. random one class of (declared classes or its implements and
	 * sub-classes)</br>
	 * Return *NULL* when not found
	 * 
	 * @param class2xmlElement
	 */
	private static IClass findFieldTarget(IField f, Object config, IClassHierarchy cha,
			Map<IClass, Set<Element>> class2xmlElement) {
		Set<String> mayTargets = new HashSet<>();
		if (config != null) {
			if (config instanceof Annotation) {
				Annotation p_anno = (Annotation) config;
				for (Entry<String, ElementValue> entry : p_anno.getNamedArguments().entrySet()) {
					ElementValue eleVal = entry.getValue();
					if (eleVal instanceof ConstantElementValue) {
						Object val0 = ((ConstantElementValue) eleVal).val;
						String val = val0.toString();
						mayTargets.add(val);
					}
				}
			} else if (config instanceof String) {
				String val = (String) config;
				mayTargets.add(val);
			}
		}

		IClass fieldDecClazz = cha.lookupClass(f.getReference().getFieldType());
		if (fieldDecClazz == null)
			return null;
		List<IClass> candidates = new ArrayList<>();
		findAllConcreteSubclasses(fieldDecClazz, cha, candidates);

		/*
		 * policy1: field-config-value v.s. class configuration value
		 */
		for (String targetVal : mayTargets) {
			for (IClass clazz : candidates) {
				// annotation vals
				for (Annotation anno : clazz.getAnnotations()) {
					for (Entry<String, ElementValue> entry : anno.getNamedArguments().entrySet()) {
						ElementValue eleVal = entry.getValue();
						if (eleVal instanceof ConstantElementValue) {
							Object val0 = ((ConstantElementValue) eleVal).val;
							// find one then return
							if (targetVal.toLowerCase().equals(val0.toString().toLowerCase()))
								return clazz;
						}
					}
				}
				// xml vals
				if (class2xmlElement.containsKey(clazz)) {
					for (Element ele : class2xmlElement.get(clazz)) {
						boolean has = XMLConfigHandler.hasClassValue(targetVal, ele);
						if (has)
							return clazz;
					}
				}
			}
		}

		/*
		 * policy2: field-config-value v.s. class declared name
		 */
		for (String targetVal : mayTargets) {
			for (IClass clazz : candidates) {
				if (targetVal.toLowerCase().equals(clazz.getName().getClassName().toString().toLowerCase()))
					return clazz;
			}
		}

		/*
		 * 3. random one class of (declared classes or its implements and sub-classes)
		 */
		if (candidates.size() != 0) {
			return candidates.get(0);
		}

		return null;
	}

	private static void findAllConcreteSubclasses(IClass clazz, IClassHierarchy cha, List<IClass> candidates) {
		if (clazz.isInterface()) {
			for (IClass sub : cha.getImplementors(clazz.getReference()))
				findAllConcreteSubclasses(sub, cha, candidates);
		} else {
			if (!clazz.isAbstract() && !candidates.contains(clazz))
				candidates.add(clazz);
			for (IClass subclazz : cha.getImmediateSubclasses(clazz))
				findAllConcreteSubclasses(subclazz, cha, candidates);
		}
	}

}
