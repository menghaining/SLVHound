package SLVHound.checker.common.cgBuilder;

public class EntryConfig implements IConfig {
	String operation;
	FrameworkConfigType type;
	String classConfig;
	String methodConfig;

	public EntryConfig(FrameworkConfigType type, String classConfig, String methodConfig) {
		this.operation = ENTRY;
		this.type = type;
		this.classConfig = classConfig;
		this.methodConfig = methodConfig;
	}

	public String getOperation() {
		return operation;
	}

	public FrameworkConfigType getType() {
		return type;
	}

	public String getClassConfig() {
		return classConfig;
	}

	public String getMethodConfig() {
		return methodConfig;
	}

}
