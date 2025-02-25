package SLVHound.checker.core.infer.dataflow;

import java.util.ArrayList;
import java.util.List;

import com.ibm.wala.analysis.typeInference.TypeInference;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.types.FieldReference;
import com.ibm.wala.types.TypeReference;

public class AccessPath {
	private int hashCode = 0;
	private final int base;
	private TypeReference baseType;
	private final CGNode node;
	private List<FieldReference> fieldRefs = new ArrayList<>();

	public AccessPath(int id, List<FieldReference> fieldRefs, CGNode node) {
		if (id == -1) {
			assert fieldRefs.size() > 0;
		}
		this.base = id;
		this.node = node;
		int maxFieldDepth = 3;
		if (fieldRefs != null) {
			if (fieldRefs.size() > maxFieldDepth) {
				for (int i = 0; i < maxFieldDepth; i++) {
					this.fieldRefs.add(fieldRefs.get(i));
				}
			} else {
				this.fieldRefs.addAll(fieldRefs);
			}
		}
	}

	//	remove the first field and return
	public List<FieldReference> cutFirstField() {
		List<FieldReference> tmpList = new ArrayList<>();
		tmpList.addAll(fieldRefs);
		if (tmpList.size() == 0)
			return tmpList;
		tmpList.remove(0);
		return tmpList;
	}

	//	add @field as first field and return
	public List<FieldReference> appendFirstField(FieldReference field) {
		List<FieldReference> tmpList = new ArrayList<>();
		tmpList.addAll(fieldRefs);
		tmpList.add(0, field);
		return tmpList;
	}

	//	add @field as last field and return
	public List<FieldReference> appendLastField(FieldReference field) {
		List<FieldReference> tmpList = new ArrayList<>();
		tmpList.addAll(fieldRefs);
		tmpList.add(field);
		return tmpList;
	}

	public TypeReference getBaseType() {
		if (baseType != null)
			return baseType;
		if (node != null) {
			TypeInference typeInference = TypeInference.make(node.getIR(), true);
			if (base >= 0) {
				baseType = typeInference.getType(base).getTypeReference();
			}
			// static
			else if (base == -1) {
				baseType = getFirstField().getDeclaringClass();
			} else if (base == -3) {
				baseType = TypeReference.Null;
			} else {
				baseType = TypeReference.Null;
			}
		} else {
			baseType = TypeReference.Null;
		}
		return baseType;
	}

	public FieldReference getFirstField() {
		if (fieldRefs.size() == 0)
			return null;
		return fieldRefs.get(0);
	}

	public boolean isStatic() {
		return base == -1;
	}

	public int getBase() {
		return base;
	}

	public CGNode getCGNode() {
		return node;
	}

	public List<FieldReference> getFieldRefs() {
		return fieldRefs;
	}

	public int getFieldLenth() {
		return fieldRefs.size();
	}

	public boolean isLocal() {
		return base > 0 && fieldRefs.size() == 0;
	}

	/**
	 * Checks whether the first field of this access path matches the given field
	 *
	 * @param field The field to check against
	 * @return True if this access path has a non-empty field list and the first
	 * field matches the given one, otherwise false
	 */
	public boolean firstFieldMatches(FieldReference field) {
		if (fieldRefs == null || fieldRefs.size() == 0) {
			return false;
		}
		if (field.equals(fieldRefs.get(0))) {
			return true;
		}
		return false;
	}

	@Override
	public AccessPath clone() {
		AccessPath a = new AccessPath(base, cloneFieldRefs(), node);
		assert a.equals(this);
		return a;
	}

	public List<FieldReference> cloneFieldRefs() {
		List<FieldReference> tmpList = new ArrayList<>();
		tmpList.addAll(fieldRefs);
		assert tmpList.equals(fieldRefs);
		return tmpList;
	}

	@Override
	public int hashCode() {
		if (hashCode != 0)
			return hashCode;
		final int prime = 31;
		int result = 1;
		result = prime * result + base;
		result = prime * result + ((fieldRefs == null) ? 0 : fieldRefs.hashCode());
		result = prime * result + ((node == null) ? 0 : node.hashCode());
		hashCode = result;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		AccessPath other = (AccessPath) obj;
		if (base != other.base)
			return false;
		if (fieldRefs == null) {
			if (other.fieldRefs != null)
				return false;
		} else if (!fieldRefs.equals(other.fieldRefs))
			return false;
		if (node == null) {
			if (other.node != null)
				return false;
		} else if (!node.equals(other.node))
			return false;
		return true;
	}

	@Override
	public String toString() {
		List<String> fieldNames = new ArrayList<>();
		fieldRefs.stream().map(field -> {
			return field.getName().toString();
		}).forEach(name -> {
			fieldNames.add(name);
		});
		return "FieldElement [valueNumber=" + this.base + ", fieldRefs=" + fieldNames + ", CGNode=" + this.node + "]";
	}
}
