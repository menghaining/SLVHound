package SLVHound.checker.core.db;

import java.util.ArrayList;
import java.util.List;

public class SQLQuery {

	String operation;
	String table;
	List<String> columnList = new ArrayList<>();
	List<String> whereList = new ArrayList<>();

	public SQLQuery(String operation, String table, List<String> columnList, List<String> whereList) {
		super();
		this.operation = operation;
		this.table = table;
		this.columnList = columnList;
		this.whereList = whereList;
	}

	public String getOperation() {
		return operation;
	}

	public String getTable() {
		return table;
	}

	public List<String> getColumnList() {
		return columnList;
	}

	public List<String> getWhereList() {
		return whereList;
	}

	@Override
	public String toString() {
		return "SQLQuery [operation=" + operation + ", table=" + table + ", columnList=" + columnList + ", whereList="
				+ whereList + "]";
	}

}
