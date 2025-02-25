package SLVHound.checker.core;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.ibm.wala.classLoader.BytecodeClass;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAInvokeInstruction;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.types.annotations.Annotation;

import com.openai.client.OpenAIClient;
import com.openai.client.okhttp.OpenAIOkHttpClient;
import com.openai.models.ChatCompletion;
import com.openai.models.ChatCompletionCreateParams;
import com.openai.models.ChatModel;

public class AuthCollecter {
	static HashSet<CGNode> loginMtds = new HashSet<>();
	static HashSet<CGNode> filterNodes = new HashSet<>();

	/**
	 * return all candidate login and filter methods</br>
	 * 
	 * @param loginMtds   records candidate login methods
	 * @param filterNodes records candidate filter methods
	 */
	public static void collectLoginsAndFilters(CallGraph cg, int flag) {
		if (flag == 0) {
			// invoke llm
			LLM(cg);
		} else {
			// regex
			Regex(cg);
		}
	}

	private static void Regex(CallGraph cg) {
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
			if (!entrySigs.contains(mtd.getSignature()))
				continue;

			String mtdName = mtd.getName().toString();

			// 1. is entry point
			String regexLogin = "(?i)\\b\\w*(?:login|signin|authenticate)\\w*\\b";
			Pattern pattern1 = Pattern.compile(regexLogin);
			Matcher matcher1 = pattern1.matcher(mtd.getName().toString().toLowerCase());
			if (matcher1.matches()) {
				loginMtds.add(cgNode);
			}

			// 2. filter / intercepter / callback
			IClass declareClass = mtd.getDeclaringClass();
			for (String interf : ((BytecodeClass<?>) declareClass).getAllInterfaceNames()) {
				// spring intercepter
				if (interf.equals("Lorg/springframework/web/servlet/HandlerInterceptor")
						|| interf.equals("Lorg/springframework/web/servlet/handler/HandlerInterceptorAdapter")) {
					if (mtdName.toLowerCase().equals("prehandle")) {
						System.out.println("[PrePROCESS] interceptor:" + mtd.getSignature());
						filterNodes.add(cgNode);
						break;
					}
				}
				if (interf.equals("Lorg/springframework/web/socket/server/HandshakeInterceptor"))
					if (mtdName.equals("beforeHandshake")) {
						System.out.println("[PrePROCESS] interceptor:" + mtd.getSignature());
						filterNodes.add(cgNode);
						break;
					}
				// javaee filter
				if (interf.equals("Ljavax/servlet/Filter")) {
					if (mtdName.toLowerCase().equals("dofilter")) {
						System.out.println("[PrePROCESS] filter:" + mtd.getSignature());
						filterNodes.add(cgNode);
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
						break;
					}
				}
		}
	}

	private static void LLM(CallGraph cg) {
		HashSet<String> entrySigs = new HashSet<>();
		cg.getEntrypointNodes().forEach(node -> {
			entrySigs.add(node.getMethod().getSignature());
		});
		Map<CGNode, Set<SSAInvokeInstruction>> RepoInvokeInstsMap = new HashMap<>();

		// Configures using the `OPENAI_API_KEY`, `OPENAI_ORG_ID` and
		// `OPENAI_PROJECT_ID` environment variables
		OpenAIClient client = OpenAIOkHttpClient.fromEnv();
		String sys = "You are an experienced and professional Java programmer with extensive experience in Web project development. Your task is to analyze Java code snippets and determine if they represent user login methods in a Java Web project.";
		String user1 = "Analyze the following Java method and determine if it is a user login method in a Java Web project. Your response must be EXACTLY 'yes' or 'no', without any additional explanation or commentary. Here is the method code:";
		String user2 = "Is the described function a web filter, interceptor, or pre-controller processing component, based on its purpose and execution timing within the framework conventions? Answer strictly 'yes' or 'no'.  Here is the method code:";
		for (CGNode cgNode : cg) {
			if (!cgNode.getMethod().getDeclaringClass().getClassLoader().getReference()
					.equals(ClassLoaderReference.Application))
				continue;
			IMethod mtd = cgNode.getMethod();
			if (mtd == null)
				continue;
			if (RepoInvokeInstsMap.containsKey(cgNode))
				continue;
			if (!entrySigs.contains(mtd.getSignature()))
				continue;

			String content = mtd.getSignature();
			content += "{";
			for (SSAInstruction inst : cgNode.getIR().getInstructions())
				content += inst.toString() + ";";
			content += "}";

			// 1. login
			ChatCompletionCreateParams params1 = ChatCompletionCreateParams.builder().addSystemMessage(sys)
					.addUserMessage(user1 + content).model(ChatModel.GPT_4O).build();
			ChatCompletion chatCompletion = client.chat().completions().create(params1);
			String answer1 = chatCompletion.choices().get(0).message().toString().toLowerCase();
			if (answer1.startsWith("yes")) {
				loginMtds.add(cgNode);
			}

			// 2. filter
			ChatCompletionCreateParams params2 = ChatCompletionCreateParams.builder().addSystemMessage(sys)
					.addUserMessage(user2 + content).model(ChatModel.GPT_4O).build();
			ChatCompletion chatCompletion2 = client.chat().completions().create(params2);
			String answer2 = chatCompletion2.choices().get(0).message().toString().toLowerCase();
			if (answer2.startsWith("yes")) {
				filterNodes.add(cgNode);
			}
		}
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

}
