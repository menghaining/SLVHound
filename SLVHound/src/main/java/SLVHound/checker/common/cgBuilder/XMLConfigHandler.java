package SLVHound.checker.common.cgBuilder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentType;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.types.ClassLoaderReference;

public class XMLConfigHandler {
	private HashMap<String, IClass> applicationClasses = new HashMap<>();

	private Map<IClass, Set<Element>> class2XMLElement = new HashMap<>();

	public static XMLConfigHandler instance(Set<String> xMLFileList, IClassHierarchy cha) {
		XMLConfigHandler obj = new XMLConfigHandler();

		/* 1. collect all application classes */
		cha.getLoader(ClassLoaderReference.Application).iterateAllClasses().forEachRemaining(clazz -> {
			obj.applicationClasses.put(FrameworkUtil.remakeType2(clazz.getReference().getName().toString()), clazz);
		});

		/* 2. collect all application classes xml configuration element */
		for (String path : xMLFileList) {
			File file = new File(path);
			SAXReader reader = new SAXReader();
			reader.setValidation(false);
			reader.setEntityResolver(new EntityResolver() {
				@Override
				public InputSource resolveEntity(String publicId, String systemId) throws SAXException, IOException {
					return new InputSource(new ByteArrayInputStream("".getBytes()));
				}
			});
			try {
				Document document = reader.read(file);
				/* exclude database configure */
				DocumentType docType = document.getDocType();
				if (docType != null)
					if (notConcernedXMLID(docType.getPublicID()) || notConcernedXMLID(docType.getSystemID()))
						continue;

				Element root = document.getRootElement();
				/* find all root that the */
				obj.praseCurrLayer(root);
			} catch (DocumentException e) {
				System.err.println("[error][DocumentException]" + e.getMessage() + " when parse " + file);
			}
		}

		return obj;
	}

	public Map<IClass, Set<Element>> getClassConfigurations() {
		return class2XMLElement;
	}

	public static boolean notConcernedXMLID(String type) {
		if (type != null) {
			if (type.toLowerCase().contains("hibernate") || type.toLowerCase().contains("mybatis")
					|| type.toLowerCase().contains("log4j") || type.toLowerCase().contains("plugin"))
				return true;
		}

		return false;
	}

	private void praseCurrLayer(Element root) {
		// text
		String text = root.getText();
		IClass tmp = findClass(text);
		if (tmp != null)
			add2Res(tmp, root);

		// attribute
		for (Object attr0 : root.attributes()) {
			if (attr0 instanceof Attribute) {
				Attribute attr = (Attribute) attr0;
				String val = attr.getValue();
				/* 3.5: collect all element about class */
				HashSet<IClass> rets = findClasses(val);

				for (IClass res : rets)
					add2Res(res, root);
			}
		}

		// traverse all children
		for (Object child0 : root.elements()) {
			if (child0 instanceof Element) {
				praseCurrLayer((Element) child0);
			}
		}
	}

	private void add2Res(IClass val, Element root) {
		if (class2XMLElement.containsKey(val)) {
			class2XMLElement.get(val).add(root);
		} else {
			HashSet<Element> tmp = new HashSet<Element>();
			tmp.add(root);
			class2XMLElement.put(val, tmp);
		}
	}

	/** @return the application class if the node contains, else null */
	private IClass findClass(String val) {
		if (val.equals(""))
			return null;
		if (val.contains("/")) {
			val = val.replaceAll("/", ".");
		}
		for (String app : applicationClasses.keySet()) {
			if (val.startsWith(app))
				return applicationClasses.get(app);
			if (app.startsWith(val))
				return applicationClasses.get(val);
			if (val.toLowerCase().equals(app.toLowerCase()))
				return applicationClasses.get(val);
		}
		return null;
	}

	/** @return the application class if the node contains, else null */
	private HashSet<IClass> findClasses(String val) {
		HashSet<IClass> ret = new HashSet<>();
		if (val.equals(""))
			return ret;
		if (val.contains("/")) {
			val = val.replaceAll("/", ".");
		}
		for (String app : applicationClasses.keySet()) {
			if (val.equals(app) || app.toLowerCase().endsWith(val.toLowerCase()))
				ret.add(applicationClasses.get(app));
		}
		return ret;
	}

	/**
	 * return as beans/bean
	 */
	public static String buildPath(Element ele) {
		String last = "/" + ele.getName();
		Element parent = ele.getParent();
		while (parent != null && !parent.equals(ele)) {
			last = "/" + parent.getName() + last;
			parent = parent.getParent();
		}
		return last;
	}

	/**
	 * return the element that indexes f from ele with sufix
	 */
	public static Element hasValue(String sufix, Element ele, String v) {
		if (sufix.startsWith("/")) {
			// element node
			for (Object child0 : ele.elements()) {
				if (child0 instanceof Element) {
					Element child = (Element) child0;
					if (sufix.startsWith("/" + child.getName())) {
						String ssfix = sufix.substring(child.getName().length() + 1);
						return hasValue(ssfix, child, v);
					}
				}
			}
		} else if (sufix.startsWith("@")) {
			// attribute
			for (Object attr0 : ele.attributes()) {
				if (attr0 instanceof Attribute) {
					Attribute attr = (Attribute) attr0;
					String name = attr.getName();
					String val = attr.getValue();
					if (sufix.equals("@" + name)) {
						if (val.toLowerCase().equals(v.toLowerCase()))
							return ele;
					}
				}
			}
			// text
			if (sufix.equals("@text")) {
				if (ele.getText().toLowerCase().equals(v.toLowerCase()))
					return ele;
			}
		}
		return null;
	}

	/**
	 * return the element/attribute value that matched sufix with ele
	 */
	public static String findPoints2Value(String sufix, Element ele) {
		if (sufix.startsWith("/")) {
			// element node
			for (Object child0 : ele.elements()) {
				if (child0 instanceof Element) {
					Element child = (Element) child0;
					if (sufix.startsWith("/" + child.getName())) {
						String ssfix = sufix.substring(child.getName().length() + 1);
						return findPoints2Value(ssfix, child);
					}
				}
			}
		} else if (sufix.startsWith("@")) {
			// attribute
			for (Object attr0 : ele.attributes()) {
				if (attr0 instanceof Attribute) {
					Attribute attr = (Attribute) attr0;
					String name = attr.getName();
					String val = attr.getValue();
					if (sufix.equals("@" + name)) {
						return val;
					}
				}
			}
		}
		return null;
	}

	/**
	 * return whether the ele contains the target value at first layer
	 */
	public static boolean hasClassValue(String target, Element ele) {
		// attribute
		for (Object attr0 : ele.attributes()) {
			if (attr0 instanceof Attribute) {
				Attribute attr = (Attribute) attr0;
				String val = attr.getValue();
				if (target.toLowerCase().equals(val.toLowerCase()))
					return true;
			}
		}
		// text
		if (ele.getText().toLowerCase().equals(target.toLowerCase()))
			return true;

		return false;
	}

}
