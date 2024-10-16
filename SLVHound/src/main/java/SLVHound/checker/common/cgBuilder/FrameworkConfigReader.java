package SLVHound.checker.common.cgBuilder;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.json.JSONArray;
import org.json.JSONObject;

public class FrameworkConfigReader {
	Set<IConfig> fieldSpecification = new HashSet<>();
	Set<IConfig> epSpecification = new HashSet<>();
	Set<IConfig> indirectCallSpecification = new HashSet<>();

	static FrameworkConfigReader reader = null;

	public static FrameworkConfigReader instance() {
		if (reader != null)
			return reader;
		reader = new FrameworkConfigReader();
		reader.read();
		return reader;
	}

	public void read() {
		try {
			String projectDir = System.getProperty("user.dir");
			String specificationPath = projectDir + "/src/main/resources/" + "frameworkConfigs.json";
			String content = FileUtils.readFileToString(new File(specificationPath), "UTF-8");
			JSONArray jsonArray = new JSONArray(content);
			jsonArray.forEach(line -> {
				if (line instanceof JSONObject) {
					JSONObject obj = (JSONObject) line;
					String operation = obj.getString("operation");
					String type = obj.getString("type");

					if (operation.equals("field_Inject")) {
						ArrayList<String> configs = new ArrayList<>();
						configs.add(obj.getString("config1"));
						configs.add(obj.getString("config2"));
						fieldSpecification.add(new FieldConfig(FrameworkConfigType.valueOf(type), configs));
					} else if (operation.equals("entry_point")) {
						epSpecification.add(new EntryConfig(FrameworkConfigType.valueOf(type), obj.getString("config1"),
								obj.getString("config2")));
					} else if (operation.equals("indirect_call")) {
						// TODO
					}
				}
			});
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public Set<IConfig> getFieldSpecification() {
		return fieldSpecification;
	}

	public Set<IConfig> getEpSpecification() {
		return epSpecification;
	}

	public Set<IConfig> getIndirectCallSpecification() {
		return indirectCallSpecification;
	}

}
