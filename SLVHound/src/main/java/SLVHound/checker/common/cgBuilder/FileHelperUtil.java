package SLVHound.checker.common.cgBuilder;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class FileHelperUtil {

	public static FileType getTypeBySuffix(String filePath) {
		if (!filePath.contains(".")) {
			return FileType.UNKOWN;
		}
		String extension = filePath.substring(filePath.lastIndexOf("."));
		switch (extension) {
		case ".xml":
			return FileType.XML;
		case ".txt":
			return FileType.TXT;
		case ".jar":
			return FileType.JAR;
		case ".war":
			return FileType.WAR;
		case ".json":
			return FileType.JSON;
		case ".class":
			return FileType.CLASS;
		case ".java":
			return FileType.JAVA;
		case ".apk":
			return FileType.APK;
		default:
			return FileType.UNKOWN;
		}
	}

	public static List<URL> iterXMLFileInJar(String jarPath) throws IOException {
		List<URL> result = new ArrayList<URL>();
		JarFile jarFile = null;
		try {
			jarFile = new JarFile(new File(jarPath));
			Enumeration<JarEntry> entries = jarFile.entries();
			while (entries.hasMoreElements()) {
				JarEntry entry = entries.nextElement();
				String entryName = entry.getName();
				if (!entry.isDirectory() && entryName.endsWith(".xml")) {
					URL url = new URL("jar:file:" + jarPath + "!/" + entry.toString());
					result.add(url);
				}
			}
		} finally {
			try {
				if (jarFile != null) {
					jarFile.close();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return result;
	}

}
