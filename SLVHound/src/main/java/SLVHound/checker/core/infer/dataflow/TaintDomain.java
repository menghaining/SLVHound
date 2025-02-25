package SLVHound.checker.core.infer.dataflow;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.stream.Stream;

import com.ibm.wala.dataflow.IFDS.PathEdge;
import com.ibm.wala.dataflow.IFDS.TabulationDomain;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;

public class TaintDomain
		implements TabulationDomain<TaintDomainElement, BasicBlockInContext<IExplodedBasicBlock>> {
	// one-to-one mapping from ICodeElement to DomainElement
	private final Map<TaintDomainElement, Integer> table;
	// A list contains all taint domain
	private final List<TaintDomainElement> objects;

	public TaintDomain(TaintDomainElement zero) {
		this.table = new HashMap<TaintDomainElement, Integer>();
		this.objects = new ArrayList<TaintDomainElement>();

		this.objects.add(zero);
		this.table.put(zero, Integer.valueOf(0));
	}

	@Override
	public TaintDomainElement getMappedObject(int n) throws NoSuchElementException {
		if (!isValidIndex(n)) {
			throw new NoSuchElementException();
		}
		return objects.get(n);
	}

	public boolean isValidIndex(int n) {

		if (n < 0 || n > objects.size()) {
			return false;
		}
		return true;
	}

	/**
	 * pre-condition: hasMappedIndex(DomainElement);
	 */
	@Override
	public int getMappedIndex(Object o) {
		return this.table.get(o);
	}

	/**
	 * for convenient reason.
	 */
	public boolean hasMappedIndex(TaintDomainElement o) {
		return this.table.containsKey(o);
	}

	@Override
	public int getMaximumIndex() {
		return this.objects.size() - 1;
	}

	@Override
	public int getSize() {
		return this.objects.size();
	}

	@Override
	// Everytime we add a taint domain, we give it a number if it is not in the
	// current table
	public int add(TaintDomainElement o) {
		Integer i = this.table.get(o);
		if (i == null) {
			i = getMaximumIndex() + 1;
			this.objects.add(o);
			this.table.put(o, i);
		}
		return i;
	}

	@Override
	public Iterator<TaintDomainElement> iterator() {
		return objects.iterator();
	}

	@Override
	public boolean hasPriorityOver(PathEdge<BasicBlockInContext<IExplodedBasicBlock>> p1,
			PathEdge<BasicBlockInContext<IExplodedBasicBlock>> p2) {
		return false;
	}

	@Override
	public Stream<TaintDomainElement> stream() {
		// TODO Auto-generated method stub
		return null;
	}

}
