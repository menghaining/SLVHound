package SLVHound.checker.core.db;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SQLParser {
	public static void main(String[] args) {
		String insertSQL = "INSERT INTO users (username, password, enabled) VALUES (?, ?, ?)";
		String deleteSQL = "DELETE FROM users WHERE username=?";
		String selectSQL = "SELECT username,password FROM users WHERE username=?";
		String updateSQL = "UPDATE users SET password = ? WHERE username=?";
		parseSql(insertSQL);
		parseSql(deleteSQL);
		parseSql(selectSQL);
		parseSql(updateSQL);
	}

	public static SQLQuery parseSql(String sql) {
		String operation = "", table = "";
		List<String> columns = new ArrayList<>();
		List<String> conditions = new ArrayList<>();

		if (sql.toUpperCase().startsWith("INSERT")) {
			Pattern pattern = Pattern
					.compile("(?i)^(INSERT)\\s+INTO\\s+(\\w+)\\s+\\((.*?)\\)\\s+VALUES\\s+\\((.*?)\\)");
			Matcher matcher = pattern.matcher(sql);
			if (matcher.find()) {
				operation = matcher.group(1).trim();
				table = matcher.group(2).trim();
				String[] columnArray = matcher.group(3).trim().split(",\\s*");
				for (String column : columnArray) {
					columns.add(column.trim());
				}
			}
		} else if (sql.toUpperCase().startsWith("DELETE")) {
			Pattern pattern = Pattern.compile("(?i)^(DELETE)\\s+FROM\\s+(\\w+)\\s+WHERE\\s+(\\w+)");
			Matcher matcher = pattern.matcher(sql);
			if (matcher.find()) {
				operation = matcher.group(1).trim();
				table = matcher.group(2).trim();
				conditions.add(matcher.group(3).trim());
			}
		} else if (sql.toUpperCase().startsWith("SELECT")) {
			Pattern pattern = Pattern.compile("(?i)^(SELECT)\\s+(.*?)\\s+FROM\\s+(\\w+)\\s+WHERE\\s+(\\w+)");
			Matcher matcher = pattern.matcher(sql);
			if (matcher.find()) {
				operation = matcher.group(1).trim();
				String[] columnArray = matcher.group(2).trim().split(",\\s*");
				for (String column : columnArray) {
					columns.add(column.trim());
				}
				table = matcher.group(3).trim();
				conditions.add(matcher.group(4).trim());
			}
		} else if (sql.toUpperCase().startsWith("UPDATE")) {
			Pattern pattern = Pattern.compile("(?i)^(UPDATE)\\s+(\\w+)\\s+SET\\s+(.*?)\\s+WHERE\\s+(\\w+)");
			Matcher matcher = pattern.matcher(sql);
			if (matcher.find()) {
				operation = matcher.group(1).trim();
				table = matcher.group(2).trim();
				String[] setClauses = matcher.group(3).trim().split(",\\s*");
				for (String clause : setClauses) {
					String column = clause.split("=")[0].trim();
					columns.add(column);
				}
				conditions.add(matcher.group(4).trim());
			}
		} else {
			return null;
		}

		return new SQLQuery(operation, table, columns, conditions);
	}

}
