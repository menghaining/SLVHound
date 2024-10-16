package SLVHound.checker.common.cgBuilder;

import java.util.List;

public class FieldConfig implements IConfig {
	String operation;
	FrameworkConfigType type;
	List<String> configs;

	public FieldConfig(FrameworkConfigType type, List<String> configs) {
		this.operation = INJECT;
		this.type = type;
		this.configs = configs;
	}

	public String getOperation() {
		return operation;
	}

	public FrameworkConfigType getType() {
		return type;
	}

	public List<String> getConfigs() {
		return configs;
	}

}
