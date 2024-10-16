package SLVHound.checker.common.cgBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IField;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.classLoader.IMethod.SourcePosition;
import com.ibm.wala.classLoader.Language;
import com.ibm.wala.classLoader.Module;
import com.ibm.wala.classLoader.ShrikeBTMethod;
import com.ibm.wala.classLoader.ShrikeClass;
import com.ibm.wala.ipa.callgraph.AnalysisCache;
import com.ibm.wala.ipa.callgraph.AnalysisCacheImpl;
import com.ibm.wala.ipa.callgraph.AnalysisOptions;
import com.ibm.wala.ipa.callgraph.AnalysisScope;
import com.ibm.wala.ipa.callgraph.Entrypoint;
import com.ibm.wala.ipa.callgraph.impl.DefaultEntrypoint;
import com.ibm.wala.ipa.callgraph.impl.Util;
import com.ibm.wala.ipa.callgraph.propagation.SSAPropagationCallGraphBuilder;
import com.ibm.wala.ipa.cha.ClassHierarchy;
import com.ibm.wala.ipa.cha.ClassHierarchyException;
import com.ibm.wala.ipa.cha.ClassHierarchyFactory;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.shrikeBT.ConstantInstruction;
import com.ibm.wala.shrikeBT.Constants;
import com.ibm.wala.shrikeBT.DupInstruction;
import com.ibm.wala.shrikeBT.IInvokeInstruction.Dispatch;
import com.ibm.wala.shrikeBT.Instruction;
import com.ibm.wala.shrikeBT.InvokeInstruction;
import com.ibm.wala.shrikeBT.LoadInstruction;
import com.ibm.wala.shrikeBT.MethodData;
import com.ibm.wala.shrikeBT.MethodEditor;
import com.ibm.wala.shrikeBT.MethodEditor.Output;
import com.ibm.wala.shrikeBT.NewInstruction;
import com.ibm.wala.shrikeBT.PutInstruction;
import com.ibm.wala.shrikeCT.InvalidClassFileException;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.types.TypeReference;
import com.ibm.wala.util.CancelException;
import com.ibm.wala.util.config.AnalysisScopeReader;
import com.ibm.wala.util.config.FileOfClasses;
import com.ibm.wala.util.io.FileProvider;

public class FrameworkUtil {

	public static void insertField(IClassHierarchy cha, Set<String> xMLFileList) {
		Map<IField, TypeReference> field2Target = Collector.collectField(cha, xMLFileList);

		// conduct insert actions
		for (Entry<IField, TypeReference> entry : field2Target.entrySet()) {
			IField field = entry.getKey();
			TypeReference target = entry.getValue();
			if (target == null)
				continue;
			IClass fieldDecClazz = field.getDeclaringClass();

			if (fieldDecClazz instanceof ShrikeClass) {
				ShrikeClass shirkeFDClazz = (ShrikeClass) fieldDecClazz;
				if (!field.isStatic()) {
					for (IMethod initMtd : shirkeFDClazz.getInitMethod()) {
						if (initMtd instanceof ShrikeBTMethod) {
							ShrikeBTMethod method = (ShrikeBTMethod) initMtd;
							InsertNewInst2Init(cha, field, target, method);
						}
					}
				}
			}
		}
		System.out.println();
	}

	/**
	 * <b>Insert policy:</b></br>
	 * 1. when target = primitive type / string, insert default constant value;</br>
	 * 2. when target = class type, new class object then insert. Insert procedure:
	 * load-new-dup-(...)-invoke-putfield. If target class constructor has
	 * parameter: at (...) position insert parameters:</br>
	 * 2.1 if parameter type is primitive or string, insert default;</br>
	 * 2.2 else: new parameter type constructor, however, if the constructor has
	 * parameter, set as primitive/string/null </br>
	 * </br>
	 * <b>Maintain information:</b></br>
	 * 1. ShrikeBTMethod.tmpInstructions/tmpHandlers/pcMap contains the modified
	 * instructions.</br>
	 * 2. ShrikeBTMethod.bcInfo.positionMap/lineNumberMap contains the
	 * {bytecode-index,srcIndex}.</br>
	 * 3. ShrikeBTMethod.Decoder.instructions/handlers/instructionsToBytecodes
	 * contains the original information from original loaded bytecode.
	 */
	private static void InsertNewInst2Init(IClassHierarchy cha, IField field, TypeReference target,
			ShrikeBTMethod method) {
		try {
			MethodData md = new MethodData(method.isPublic() ? Constants.ACC_PUBLIC : Constants.ACC_PRIVATE,
					method.getDeclaringClass().getName().toString(), method.getReference().getName().toString(),
					method.getSelector().getDescriptor().toString(), method.getInstructions(), method.getHandlers(),
					method.getInstructionsToBytecodes());

			String fieldType = target.getName().toString();
			String fieldName = field.getName().toString();

			int insertCount = 0;
			// consider: target is array, strats with '['
			int dimension = calculateDimensions(fieldType);
			int len = 0;
			if (dimension > 0) {
				ArrayList<Instruction> instructionList = new ArrayList<>();
				// array
				instructionList.add(LoadInstruction.make(Constants.TYPE_Object, 0));
				for (int i = 0; i < dimension; i++) {
					// array length for per dimension
					instructionList.add(ConstantInstruction.make(len));
				}
				instructionList.add(NewInstruction.make(makeType(fieldType), dimension));// dimension
				instructionList
						.add(PutInstruction.make(makeType(field.getReference().getFieldType().getName().toString()),
								makeType(field.getDeclaringClass().getReference().getName().toString()), fieldName,
								field.isStatic()));
				insertCount = InsertInstructions(md, method.getInstructions().length - 2, instructionList);
			} else {
				if (target.isPrimitiveType()) {
					/* load-const-put */
					ArrayList<Instruction> instructions = new ArrayList<>();
					genPrimitiveInstruction(instructions, target);
					ArrayList<Instruction> instructionList = new ArrayList<>();
					if (instructions.size() > 0) {
						instructionList.add(LoadInstruction.make(Constants.TYPE_Object, 0));
						for (Instruction inst : instructions)
							instructionList.add(inst);
						instructionList.add(PutInstruction.make(fieldType,
								makeType(field.getDeclaringClass().getReference().getName().toString()), fieldName,
								field.isStatic()));
					}
					insertCount = InsertInstructions(md, method.getInstructions().length - 2, instructionList);
				} else if (target.getName().toString().equals("Ljava/lang/String")) {
					/* load-const-put */
					ArrayList<Instruction> instructionList = new ArrayList<>();
					instructionList.add(LoadInstruction.make(Constants.TYPE_Object, 0));
					instructionList.add(ConstantInstruction.makeString(""));
					instructionList.add(PutInstruction.make(makeType(fieldType),
							makeType(field.getDeclaringClass().getReference().getName().toString()), fieldName,
							field.isStatic()));
					insertCount = InsertInstructions(md, method.getInstructions().length - 2, instructionList);
				} else {
					/* load-new-dup-(param...)-invoke-put */
					boolean broken = false;
					IClass targetClazz = cha.lookupClass(target);
					if (targetClazz != null) {
						IMethod initMethod = getInitMethod(targetClazz);
						if (initMethod != null) {
							ArrayList<Instruction> instructionList = new ArrayList<>();
							instructionList.add(LoadInstruction.make(Constants.TYPE_Object, 0));
							instructionList.add(NewInstruction.make(makeType(targetClazz.getName().toString()), 0));
							instructionList.add(DupInstruction.make(0));
							/* consider <init> parameters */
							if (initMethod.getNumberOfParameters() > 1) {
								ArrayList<Instruction> paramInstructionList = new ArrayList<>();
								broken = genNewParameters(paramInstructionList, initMethod, cha, 0);
								instructionList.addAll(paramInstructionList);
							}
							instructionList
									.add(InvokeInstruction.make(initMethod.getSelector().getDescriptor().toString(),
											makeType(targetClazz.getName().toString()), initMethod.getName().toString(),
											Dispatch.SPECIAL));
							instructionList.add(PutInstruction.make(
									makeType(field.getReference().getFieldType().getName().toString()),
									makeType(field.getDeclaringClass().getName().toString()),
									field.getName().toString(), field.isStatic()));
							if (!broken)
								insertCount = InsertInstructions(md, method.getInstructions().length - 2,
										instructionList);
						}
					}
				}
			}

			/* write back to original method */
			if (insertCount > 0) {
				method.setCachedInstructions(md.getInstructions());
				method.setCachedHandlers(md.getHandlers());
				int[] inst2b1 = md.getInstructionsToBytecodes();
				for (int i = inst2b1.length - 2; i > inst2b1.length - 2 - insertCount; i--) {
					inst2b1[i] = inst2b1[inst2b1.length - 1];
				}
				method.setCachedInstructionsToBytecodes(md.getInstructionsToBytecodes());
				/* update source position after inserted instructions */
				// as the last line of this method
				SourcePosition[] oldSrcpos = method.getCachedSourcePositions();
				SourcePosition[] newSrcpos = new SourcePosition[oldSrcpos.length + insertCount];
				for (int i = 0; i < oldSrcpos.length; i++)
					newSrcpos[i] = oldSrcpos[i];
				for (int i = oldSrcpos.length; i < oldSrcpos.length + insertCount; i++)
					newSrcpos[i] = oldSrcpos[oldSrcpos.length - 1];
				method.setCachedSourcePositions(newSrcpos);
				// update linenumbermap after inserted instructions
				int[] oldline = method.getCachedLineNumberMap();
				int[] newline = new int[oldline.length + insertCount];
				for (int i = 0; i < oldline.length; i++)
					newline[i] = oldline[i];
				for (int i = oldline.length; i < oldline.length + insertCount; i++)
					newline[i] = oldline[oldline.length - 1];
				method.setCachedLineNumberMap(newline);
			}
		} catch (InvalidClassFileException e) {
			e.printStackTrace();
		}
	}

	private static int calculateDimensions(String fieldType) {
		int index = fieldType.lastIndexOf('[');

		return index + 1;
	}

	private static boolean genNewParameters(ArrayList<Instruction> paramInstructionList, IMethod initMethod,
			IClassHierarchy cha, int curr) {
		boolean broken = false;
		if (curr == 1) {
			// set unknown class as NULL
			for (int j = 1; j < initMethod.getNumberOfParameters(); j++) {
				TypeReference paramparamType = initMethod.getParameterType(j);
				if (paramparamType.isPrimitiveType())
					genPrimitiveInstruction(paramInstructionList, paramparamType);
				else if (paramparamType.getName().toString().equals("Ljava/lang/String"))
					paramInstructionList.add(ConstantInstruction.makeString(""));
				else
					paramInstructionList.add(ConstantInstruction.make(Constants.TYPE_Object, null));
			}
		} else {
			for (int i = 1; i < initMethod.getNumberOfParameters(); i++) {
				TypeReference paramType = initMethod.getParameterType(i);
				if (paramType.isPrimitiveType())
					genPrimitiveInstruction(paramInstructionList, paramType);
				else if (paramType.getName().toString().equals("Ljava/lang/String"))
					paramInstructionList.add(ConstantInstruction.makeString(""));
				else {
					IClass paramClazz = cha.lookupClass(paramType);
					if (paramClazz == null) {
						broken = true;
						break;
					}
					IMethod paramInitMtd = getInitMethod(paramClazz);
					if (paramInitMtd == null) {
						broken = true;
						break;
					}
					/** new-dup-invoke */
					paramInstructionList.add(NewInstruction.make(makeType(paramType.getName().toString()), 0));
					paramInstructionList.add(DupInstruction.make(0));
					if (paramInitMtd.getNumberOfParameters() > 1) {
						if (genNewParameters(paramInstructionList, paramInitMtd, cha, curr + 1)) {
							broken = true;
							break;
						}
					}
					paramInstructionList
							.add(InvokeInstruction.make(paramInitMtd.getSelector().getDescriptor().toString(),
									makeType(paramClazz.getName().toString()), paramInitMtd.getName().toString(),
									Dispatch.SPECIAL));
				}
			}
		}
		return broken;
	}

	/**
	 * represent as an internal JVM type name ('/' separated, starting with 'L' and
	 * ending with ';').
	 */
	public static String makeType(String str) {
		if (str.contains("/") && (str.startsWith("L") || str.startsWith("[")))
			return str + ";";
		return str;
	}

	/**
	 * convert example.package.A to Lexample/package/A, without ; at end
	 */
	public static String makeType2(String str) {
		return "L" + str.replace('.', '/');
	}

	/**
	 * convert Lexample/package/A (without ; at end) to example.package.A
	 */
	public static String remakeType2(String str) {
		if (str.startsWith("L") && str.contains("/"))
			return str.substring(1).replace('/', '.');
		return str;
	}

	private static int InsertInstructions(MethodData md, int pos, ArrayList<Instruction> instructionList) {
		int ret = -1;
		MethodEditor me = new MethodEditor(md);

		me.beginPass();
		me.insertAfter(pos, new MethodEditor.Patch() {
			@Override
			public void emitTo(Output w) {
				for (Instruction inst : instructionList) {
					w.emit(inst);
				}
			}
		});
		boolean changed = me.applyPatches();
		me.endPass();

		if (changed)
			ret = instructionList.size();

		return ret;
	}

	private static void genPrimitiveInstruction(ArrayList<Instruction> instructionList, TypeReference type) {
		String typeAtr = type.getName().toString();
		switch (typeAtr) {
		case "I":
		case "C":
		case "Z":
		case "B":
		case "S":
			instructionList.add(ConstantInstruction.make(0));
			break;
		case "J":
			instructionList.add(ConstantInstruction.make(0l));
			break;
		case "F":
			instructionList.add(ConstantInstruction.make(0.0f));
		case "D":
			instructionList.add(ConstantInstruction.make(0.00));
			break;
		default:
			break;
		}
	}

	/** return one of the init methods of clazz, default <init>()V in priority */
	private static IMethod getInitMethod(IClass clazz) {
		IMethod targetInitmethod = null;
		if (clazz instanceof ShrikeClass) {
			ShrikeClass targetShirkeclass = (ShrikeClass) clazz;
			Set<IMethod> targetInitMethods = targetShirkeclass.getInitMethod();
			for (IMethod initmethod : targetInitMethods) {
				if (initmethod.toString().contains(" <init>()V")) {
					targetInitmethod = initmethod;
					break;
				} else {
					targetInitmethod = initmethod;
				}
			}
		}

		return targetInitmethod;
	}

	public static SSAPropagationCallGraphBuilder createMyCgBuilder(String appPath) {
		Set<String> XMLFileList = new HashSet<>();
		iterateXMLFiles(new File(appPath), XMLFileList);
		
		String projectDir = System.getProperty("user.dir");
		String resources = projectDir + "/src/main/resources";
		
		String initScopeFile = resources.concat(File.separator).concat("initScopeFile.txt");
		String exclusions = resources.concat(File.separator).concat("Java60RegressionExclusions.txt");

		AnalysisScope scope;
		try {
			scope = AnalysisScopeReader.readJavaScope(initScopeFile, null, FrameworkUtil.class.getClassLoader());
			loadFiles(scope, appPath);
			File exclusionsFile = exclusions != null ? new File(exclusions) : null;
			if (exclusionsFile != null) {
				try (final InputStream fs = exclusionsFile.exists() ? new FileInputStream(exclusionsFile)
						: FileProvider.class.getClassLoader().getResourceAsStream(exclusionsFile.getName())) {
					scope.setExclusions(new FileOfClasses(fs));
				}
			}

			ClassHierarchy cha = ClassHierarchyFactory.makeWithPhantom(scope);
//			cha.getLoader(ClassLoaderReference.Application).iterateAllClasses().forEachRemaining(x->{
//				System.out.println(x);
//			});
			/* insert new instruction for field in cha */
			insertField(cha, XMLFileList);
			/* find all entry methods */
			Set<IMethod> entryMtds = Collector.collectEntryMethod(cha, XMLFileList);
			Set<IMethod> abstractEntry = new HashSet<>();
			Set<Entrypoint> entrypoints = new HashSet<>();
			for (IMethod mtd : entryMtds) {
				entrypoints.add(new DefaultEntrypoint(mtd, cha));
				if (mtd.getDeclaringClass().isAbstract())
					abstractEntry.add(mtd);
//				System.out.println("[CG][EntryPoints] " +  mtd.getSignature());
			}
			AnalysisOptions options = new AnalysisOptions(scope, entrypoints);
			AnalysisCache cache = new AnalysisCacheImpl();
			SSAPropagationCallGraphBuilder builder = Util.makeZeroCFABuilder(Language.JAVA, options, cache, cha, scope);
//			SSAPropagationCallGraphBuilder builder = Util.makeZeroOneCFABuilder(Language.JAVA, options, cache, cha, scope);
			try {
				builder.makeCallGraph(options);
				System.out.println("[before rebuild]" + builder.getCallGraph().getMaxNumber());
				CGHelper.rebuild(builder, abstractEntry);
				System.out.println("[after rebuild]" + builder.getCallGraph().getMaxNumber());
				return builder;
			} catch (IllegalArgumentException | CancelException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassHierarchyException e) {
			e.printStackTrace();
		}
		return null;
	}

	private static void iterateXMLFiles(File file, Set<String> XMLFileList) {
		File[] fs = file.listFiles();
		if (fs == null)
			return;
		for (File f : fs) {
			if (f.isDirectory())
				iterateXMLFiles(f, XMLFileList);
			if (f.isFile()) {
				if (f.getName().endsWith(".xml")) {
					if (!XMLFileList.contains(f.getPath()))
						XMLFileList.add(f.getPath());
				}
			}
		}
	}

	private static void loadFiles(AnalysisScope scope, String filePath) {
		File file = new File(filePath);
		if (file.exists()) {
			if (file.isDirectory()) {
				File[] files = file.listFiles();
				for (File subFile : files) {
					loadFiles(scope, subFile.getAbsolutePath());
				}
			} else {
				switch (FileHelperUtil.getTypeBySuffix(filePath)) {
				case JAR:
				case WAR:
					if (concernedJars(filePath)) {
						try {
							Module M = (new FileProvider()).getJarFileModule(filePath,
									FrameworkUtil.class.getClassLoader());
							scope.addToScope(ClassLoaderReference.Primordial, M);
							System.out.println("ADD Jar into Analysis Scope: " + filePath);
						} catch (IOException e) {
							e.printStackTrace();
						}
						break;
					}

				case CLASS:
					try {
						scope.addClassFileToScope(ClassLoaderReference.Application, new File(filePath));
//						System.out.println("ADD File into Analysis Scope: " + filePath);
					} catch (IllegalArgumentException | InvalidClassFileException e1) {
						System.err.println("Cannot load file : " + filePath);
					}
					break;
				case JAVA:
//					scope.addSourceFileToScope(ClassLoaderReference.Application, new File(filePath), filePath);
					break;
				default:
					break;
				}
			}
		}

	}

	private static boolean concernedJars(String filePath) {
//		String[] strs = filePath.split("/");
//		String name = strs[strs.length - 1];
//		if (name.toLowerCase().contains("spring") || name.toLowerCase().contains("struts")
////				|| name.toLowerCase().contains("sql")
//				)
//			return true;
		return false;
	}

}
