package SLVHound.checker.core.Util;

import java.util.HashSet;
import java.util.Set;

import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.types.FieldReference;
import com.ibm.wala.types.TypeReference;

public class RepoElement {
	public static String frmk = "FRAMEWORK";
	public static String shiro = "APACHESHIRO";
	public static String springsecurity = "SPRINGSECURITY";
	public static RepoElement shiroEle = new RepoElement(null, null, RepoElement.shiro, true, null);
	public static RepoElement springSecurityEle = new RepoElement(null, null, RepoElement.springsecurity, true, null);
	public static RepoElement JWT = new RepoElement(null, null, "JWT", true, null);
	public static RepoElement frmkEle = new RepoElement(null, null, RepoElement.frmk, true, null);

	public boolean inject = false;
	public IClass belong2Class;
	public TypeReference type;
	public String name;
	public BasicBlockInContext<IExplodedBasicBlock> originalbb = null;

	public HashSet<FieldReference> ORMFields = new HashSet<>();

	public void addORMField(FieldReference fr) {
		ORMFields.add(fr);
	}

	public void addORMFields(Set<FieldReference> frs) {
		ORMFields.addAll(frs);
	}

	public RepoElement(IClass belong2Class, TypeReference type, String name, boolean inject,
			BasicBlockInContext<IExplodedBasicBlock> bb) {
		this.inject = inject;
		this.belong2Class = belong2Class;
		this.type = type;
		this.name = name;
		originalbb = bb;
	}

	public RepoElement(IClass belong2Class, TypeReference type, String name) {
		this.belong2Class = belong2Class;
		this.type = type;
		this.name = name;
	}

	public RepoElement(String string) {
		name = string;
	}

	public TypeReference getElementClass() {
		if (inject)
			return type;
		else
			return belong2Class.getReference();
	}

	public TypeReference getBaseType() {
		return type;
	}

	public IClass getBelong2Class() {
		return belong2Class;
	}

	public String getName() {
		return name;
	}

	boolean isInject() {
		return inject;
	}

	@Override
	public String toString() {
		return "[" + belong2Class + "]" + name + ":" + type + ":" + inject;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj instanceof RepoElement) {
			RepoElement object = (RepoElement) obj;
			if (inject == object.inject && belong2Class.equals(object.belong2Class) && type.equals(object.type)
					&& name.equals(object.name) && originalbb.equals(object.originalbb))
				return true;
		}

		return false;
	}

	public static HashSet<RepoElement> getFrameworkAuthRepos() {
		HashSet<RepoElement> result = new HashSet<>();
		result.addAll(getSpringSecurityAuthRepos());
		result.addAll(getApacheShrioAuthRepos());
		return result;
	}
	public static HashSet<RepoElement> getSpringSecurityAuthRepos() {
		HashSet<RepoElement> result = new HashSet<>();

		TypeReference SessionInformation = TypeReference.findOrCreate(ClassLoaderReference.Primordial,
				"Lorg/springframework/security/core/session/SessionInformation");
		TypeReference SpringSessionBackedSessionInformation = TypeReference.findOrCreate(
				ClassLoaderReference.Primordial,
				"Lorg/springframework/session/security/SpringSessionBackedSessionInformation");
		TypeReference SessionRepository = TypeReference.findOrCreate(ClassLoaderReference.Primordial,
				"Lorg/springframework/session/SessionRepository");
		TypeReference JdbcIndexedSessionRepository = TypeReference.findOrCreate(ClassLoaderReference.Primordial,
				"Lorg/springframework/session/jdbc/JdbcIndexedSessionRepository");
		TypeReference MapSessionRepository = TypeReference.findOrCreate(ClassLoaderReference.Primordial,
				"Lorg/springframework/session/MapSessionRepository");
		result.add(new RepoElement(null, SessionInformation, RepoElement.springsecurity, true, null));
		result.add(
				new RepoElement(null, SpringSessionBackedSessionInformation, RepoElement.springsecurity, true, null));
		result.add(new RepoElement(null, SessionRepository, RepoElement.springsecurity, true, null));
		result.add(new RepoElement(null, JdbcIndexedSessionRepository, RepoElement.springsecurity, true, null));
		result.add(new RepoElement(null, MapSessionRepository, RepoElement.springsecurity, true, null));

		return result;
	}

	public static HashSet<RepoElement> getApacheShrioAuthRepos() {
		HashSet<RepoElement> result = new HashSet<>();
		TypeReference DefaultSessionManager = TypeReference.findOrCreate(ClassLoaderReference.Primordial,
				"Lorg/apache/shiro/session/mgt/DefaultSessionManager");
		TypeReference DefaultWebSessionManager = TypeReference.findOrCreate(ClassLoaderReference.Primordial,
				"Lorg/apache/shiro/session/mgt/DefaultWebSessionManager");
		TypeReference SessionDAO = TypeReference.findOrCreate(ClassLoaderReference.Primordial,
				"Lorg/apache/shiro/session/mgt/eis/SessionDAO");
		TypeReference AbstractSessionDAO = TypeReference.findOrCreate(ClassLoaderReference.Primordial,
				"Lorg/apache/shiro/session/mgt/eis/AbstractSessionDAO");
		TypeReference CachingSessionDAO = TypeReference.findOrCreate(ClassLoaderReference.Primordial,
				"Lorg/apache/shiro/session/mgt/eis/CachingSessionDAO");
		TypeReference EnterpriseCacheSessionDAO = TypeReference.findOrCreate(ClassLoaderReference.Primordial,
				"Lorg/apache/shiro/session/mgt/eis/EnterpriseCacheSessionDAO");
		TypeReference MemorySessionDAO = TypeReference.findOrCreate(ClassLoaderReference.Primordial,
				"Lorg/apache/shiro/session/mgt/eis/MemorySessionDAO");
		result.add(new RepoElement(null, DefaultSessionManager, RepoElement.shiro, true, null));
		result.add(new RepoElement(null, DefaultWebSessionManager, RepoElement.shiro, true, null));
		result.add(new RepoElement(null, SessionDAO, RepoElement.shiro, true, null));
		result.add(new RepoElement(null, AbstractSessionDAO, RepoElement.shiro, true, null));
		result.add(new RepoElement(null, CachingSessionDAO, RepoElement.shiro, true, null));
		result.add(new RepoElement(null, EnterpriseCacheSessionDAO, RepoElement.shiro, true, null));
		result.add(new RepoElement(null, MemorySessionDAO, RepoElement.shiro, true, null));
		return result;
	}
}
