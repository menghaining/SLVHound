package SLVHound.checker.core;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.ibm.wala.classLoader.BytecodeClass;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.shrikeCT.AnnotationsReader.ElementValue;
import com.ibm.wala.ssa.SSAInvokeInstruction;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.types.annotations.Annotation;

public class AuthCollecter {
	static HashSet<CGNode> loginMtds = new HashSet<>();
	static HashSet<CGNode> filterNodes = new HashSet<>();

	/**
	 * return all candidate login and filter methods</br>
	 * 
	 * @param loginMtds   records candidate login methods
	 * @param filterNodes records candidate filter methods
	 */
	public static void collectLoginsAndFilters(CallGraph cg) {
		int login = 0, filter = 0;
		HashSet<String> entrySigs = new HashSet<>();
		cg.getEntrypointNodes().forEach(node -> {
			entrySigs.add(node.getMethod().getSignature());
		});
		Map<CGNode, Set<SSAInvokeInstruction>> RepoInvokeInstsMap = new HashMap<>();

		for (CGNode cgNode : cg) {
			if (!cgNode.getMethod().getDeclaringClass().getClassLoader().getReference()
					.equals(ClassLoaderReference.Application))
				continue;
			IMethod mtd = cgNode.getMethod();
			if (mtd == null)
				continue;

			if (RepoInvokeInstsMap.containsKey(cgNode))
				continue;

			String mtdName = mtd.getName().toString();

			// is entry point
			if (entrySigs.contains(mtd.getSignature())) {
				// is login method
//				if (mayLoginMethod_openai(mtd)) {
				if (loginMethod(mtd)) {
					loginMtds.add(cgNode);
					login++;
				}
			}

			// filter / intercepter / callback
			IClass declareClass = mtd.getDeclaringClass();
			for (String interf : ((BytecodeClass<?>) declareClass).getAllInterfaceNames()) {
				// spring intercepter
				if (interf.equals("Lorg/springframework/web/servlet/HandlerInterceptor")
						|| interf.equals("Lorg/springframework/web/servlet/handler/HandlerInterceptorAdapter")) {
					if (mtdName.toLowerCase().equals("prehandle")) {
						System.out.println("[PrePROCESS] interceptor:" + mtd.getSignature());
						filterNodes.add(cgNode);
						filter++;
						break;
					}
				}
				if (interf.equals("Lorg/springframework/web/socket/server/HandshakeInterceptor"))
					if (mtdName.equals("beforeHandshake")) {
						System.out.println("[PrePROCESS] interceptor:" + mtd.getSignature());
						filterNodes.add(cgNode);
						filter++;
						break;
					}
				// javaee filter
				if (interf.equals("Ljavax/servlet/Filter")) {
					if (mtdName.toLowerCase().equals("dofilter")) {
						System.out.println("[PrePROCESS] filter:" + mtd.getSignature());
						filterNodes.add(cgNode);
						filter++;
						break;
					}

				}
			}
			// spring filter
			Collection<String> spclazzs = ((BytecodeClass<?>) declareClass).getAllSuperClasses();
			for (String spclazz : spclazzs)
				if (spclazz.equals("Lorg/springframework/web/filter/OncePerRequestFilter") || spclazz
						.equals("Lorg/springframework/security/web/authentication/www/BasicAuthenticationFilter")) {
					if (mtdName.toLowerCase().equals("dofilterinternal")) {
						System.out.println("[PrePROCESS] filter:" + mtd.getSignature());
						filterNodes.add(cgNode);
						filter++;
						break;
					}
				}
			if (mtd.getAnnotations() != null) {
				for (Annotation anno : mtd.getAnnotations()) {
					String annoname = anno.getType().getName().toString();
					if (annoname.equals("Lcom/corundumstudio/socketio/annotation/OnConnect")
							|| annoname.equals("Lcom/corundumstudio/socketio/annotation/OnEvent")) {
						System.out.println("[PrePROCESS] callback:" + mtd.getSignature());
						filterNodes.add(cgNode);
						filter++;
						break;
					}
				}
			}
		}
		System.out.println("[login counts]" + login);
		System.out.println("[filter counts]" + filter);
	}

	private static boolean loginMethod(IMethod mtd) {

		// 1. common login function
		if (mayCustomLoginMethod(mtd)) {
			return true;
		}

		// 2. may framework
		if (mayFrameworkLogin(mtd)) {
			return true;
		}

		return false;
	}

	public static boolean mayFrameworkLogin(IMethod mtd) {
		// extends or implements framework API
		String mtdName = mtd.getName().toString();
		boolean mayFrameworkImpl = false;
		if (!((BytecodeClass<?>) mtd.getDeclaringClass()).getAllInterfaceNames().isEmpty())
			mayFrameworkImpl = true;
		else {
			for (String sp : ((BytecodeClass<?>) mtd.getDeclaringClass()).getAllSuperClasses()) {
				if (!sp.equals("Ljava/lang/Object")) {
					mayFrameworkImpl = true;
					break;
				}
			}
		}
		Collection<Annotation> annos = mtd.getDeclaringClass().getAnnotations();
		if (annos != null) {
			for (Annotation anno : annos) {
				String name = anno.getType().getName().toString();
				if (name.equals("Lorg/springframework/context/annotation/Configuration")) {
					mayFrameworkImpl = true;
					break;
				}
			}
		}
		if (mayFrameworkImpl) {
			// 2. spring security
			if (mtdName.equals("loadUserByUsername") || mtdName.equals("authenticate") || mtd.getSignature()
					.endsWith("Lorg/springframework/security/core/userdetails/UserDetailsService;")) {
				return true;
			}
			// 3. apache shiro
			if (mtdName.equals("doGetAuthenticationInfo")) {
				return true;
			}
		}
		return false;
	}

	/** ask openAI for whether current mtd is login **/
	private static boolean mayLoginMethod_openai(IMethod mtd) {
		return openai_login(mtd);
	}

	private static boolean mayCustomLoginMethod(IMethod mtd) {
		if (mtd.getName().toString().toLowerCase().startsWith("update")
				|| mtd.getName().toString().toLowerCase().startsWith("set")
				|| mtd.getName().toString().toLowerCase().startsWith("get")
				|| mtd.getName().toString().toLowerCase().startsWith("save")
				|| mtd.getName().toString().toLowerCase().startsWith("add")
				|| mtd.getName().toString().toLowerCase().contains("delete")
				|| mtd.getName().toString().toLowerCase().equals("init")
				|| mtd.getName().toString().toLowerCase().equals("<init>"))
			return false;
		if (mtd.getName().toString().toLowerCase().contains("login"))
			return true;

		String regex = ".*(log.*in|sign.*in).*";
		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(mtd.getName().toString().toLowerCase());
		if (matcher.matches())
			return true;

		// annotations value
		Collection<Annotation> annos = mtd.getAnnotations();
		if (annos != null)
			for (Annotation anno : annos) {
				if (anno.toString().contains("Lio/swagger/v3/oas/annotations/Parameters"))
					continue;
				if (anno.getType().getName().toString().contains("AccessLogAnnotation"))
					continue;
				for (Entry<String, ElementValue> entry : anno.getNamedArguments().entrySet()) {
					ElementValue eleVal = entry.getValue();
					if (eleVal.toString().contains("login"))
						return true;
				}
			}

		return false;
	}

	private static boolean openai_login(IMethod mtd) {
		// TODO Auto-generated method stub
		return false;
	}
}
