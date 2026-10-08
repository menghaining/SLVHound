package SLVHound.checker.core.report;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.json.JSONArray;
import org.json.JSONObject;

import com.ibm.wala.ipa.callgraph.CGNode;

import SLVHound.checker.core.Util.RepoElement;

/**
 * Persists a compact machine-readable summary for each completed analysis.
 * Reports are written outside the analyzed application so they can also be
 * produced when the input is a jar rather than a directory.
 */
public final class AnalysisReportWriter {
	private static final int MAX_REPORTS = 20;
	private static final String REPORT_SUFFIX = ".slvhound.json";

	private AnalysisReportWriter() {
	}

	public static Path write(String applicationPath, Map<RepoElement, HashSet<CGNode>> findings,
			int analyzedRepositoryCount, long elapsedMillis) throws IOException {
		Path reportDirectory = Paths.get(System.getProperty("user.dir"), "reports");
		Files.createDirectories(reportDirectory);

		JSONObject report = new JSONObject();
		report.put("application", applicationPath);
		report.put("generated_at", Instant.now().toString());
		report.put("elapsed_ms", elapsedMillis);
		report.put("analyzed_repository_count", analyzedRepositoryCount);
		report.put("affected_repository_count", findings.size());
		report.put("affected_repository_percent",
				calculateAffectedPercentage(findings.size(), analyzedRepositoryCount));
		report.put("finding_count", countFindings(findings));
		report.put("findings", buildFindingDetails(findings));

		Path reportPath = reportDirectory.resolve(createFileName(applicationPath));
		Files.write(reportPath, report.toString(2).getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE,
				StandardOpenOption.TRUNCATE_EXISTING);
		pruneOldReports(reportDirectory);
		return reportPath;
	}

	private static int calculateAffectedPercentage(int affectedCount, int analyzedCount) {
		if (analyzedCount == 0) {
			return 0;
		}
		return affectedCount / analyzedCount * 100;
	}

	private static int countFindings(Map<RepoElement, HashSet<CGNode>> findings) {
		int count = 0;
		for (HashSet<CGNode> nodes : findings.values()) {
			count += nodes.size();
		}
		return count;
	}

	private static JSONArray buildFindingDetails(Map<RepoElement, HashSet<CGNode>> findings) {
		List<Map.Entry<RepoElement, HashSet<CGNode>>> entries = new ArrayList<>(findings.entrySet());
		entries.sort(Comparator.comparing(entry -> repositoryName(entry.getKey())));

		JSONArray details = new JSONArray();
		for (Map.Entry<RepoElement, HashSet<CGNode>> entry : entries) {
			JSONObject detail = new JSONObject();
			detail.put("repository", repositoryName(entry.getKey()));
			detail.put("storage_type", storageType(entry.getKey()));

			List<String> vulnerableMethods = entry.getValue().stream()
					.map(node -> node.getMethod().getSignature())
					.sorted()
					.collect(Collectors.toList());
			detail.put("vulnerable_methods", new JSONArray(vulnerableMethods));
			details.put(detail);
		}
		return details;
	}

	private static String repositoryName(RepoElement repository) {
		if (repository.getName() != null) {
			return repository.getName();
		}
		if (repository.getBelong2Class() != null) {
			return repository.getBelong2Class().getName().toString();
		}
		return "unknown";
	}

	private static String storageType(RepoElement repository) {
		if (repository.getBaseType() != null) {
			return repository.getBaseType().getName().toString();
		}
		return "unspecified";
	}

	private static String createFileName(String applicationPath) {
		String name = Paths.get(applicationPath).getFileName().toString();
		String normalized = name.replaceAll("[^A-Za-z0-9._-]", "_");
		return normalized + "-" + System.currentTimeMillis() + REPORT_SUFFIX;
	}

	private static void pruneOldReports(Path reportDirectory) throws IOException {
		List<Path> reports = Files.list(reportDirectory)
				.filter(path -> path.getFileName().toString().endsWith(REPORT_SUFFIX))
				.sorted(Comparator.comparingLong(AnalysisReportWriter::lastModified).reversed())
				.collect(Collectors.toList());
		for (int index = MAX_REPORTS; index < reports.size(); index++) {
			Files.deleteIfExists(reports.get(index));
		}
	}

	private static long lastModified(Path path) {
		try {
			return Files.getLastModifiedTime(path).toMillis();
		} catch (IOException ignored) {
			return Long.MIN_VALUE;
		}
	}
}
