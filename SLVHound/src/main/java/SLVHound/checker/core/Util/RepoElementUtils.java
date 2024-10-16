package SLVHound.checker.core.Util;

import java.util.Set;

public class RepoElementUtils {
	/** return the ele in eles that equals re, else return null */
	public static RepoElement contains(Set<RepoElement> eles, RepoElement re) {
		for (RepoElement ele : eles) {
			if (ele.belong2Class.equals(re.belong2Class) && ele.inject == re.inject && ele.name.equals(re.name)
					&& ele.type.equals(re.type)) {
				return ele;
			}
		}
		return null;
	}
	
	/**
	 * if eles contains re, merge the fields, and return false;</br>
	 * if eles does not contains re, return true
	 */
	public static boolean notDuplicated(RepoElement re, Set<RepoElement> eles) {
		for (RepoElement ele : eles) {
			if (ele.belong2Class.equals(re.belong2Class) && ele.inject == re.inject && ele.name.equals(re.name)
					&& ele.type.equals(re.type)) {
				if (!re.ORMFields.isEmpty())
					ele.addORMFields(re.ORMFields);
				return false;
			}
		}
		return true;
	}
}
