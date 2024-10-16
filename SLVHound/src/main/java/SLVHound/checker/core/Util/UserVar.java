package SLVHound.checker.core.Util;

import java.util.HashMap;
import java.util.HashSet;

import com.ibm.wala.types.FieldReference;
import com.ibm.wala.types.TypeReference;

public class UserVar {

	public RepoElement tableAgent;

	public HashMap<TypeReference, HashSet<String>> table2Cloumns = new HashMap<>();
	public HashMap<TypeReference, HashSet<FieldReference>> clazz2fields = new HashMap<>();
	
	public HashMap<String, HashSet<String>> tableName2Cloumns = new HashMap<>();

	public HashMap<String, HashSet<String>> getTableName2Cloumns() {
		return tableName2Cloumns;
	}

	public UserVar(RepoElement t) {
		this.tableAgent = t;
	}

	public HashMap<TypeReference, HashSet<FieldReference>> getClazz2fields() {
		return clazz2fields;
	}

	public HashMap<TypeReference, HashSet<String>> getTable2Cloumns() {
		return table2Cloumns;
	}

}
