package SLVHound.checker.core;

import java.io.IOException;

import com.ibm.wala.ipa.callgraph.propagation.SSAPropagationCallGraphBuilder;

import SLVHound.checker.common.cgBuilder.FrameworkUtil;

public class Main {
	public static void main(String[] args) {
		String appPath = args[0];
		
		long startTime = System.currentTimeMillis();
		System.out.println("[START]" + appPath);
		
		long startCGTime = System.currentTimeMillis();
		SSAPropagationCallGraphBuilder builder = FrameworkUtil.createMyCgBuilder(appPath);
		long endCGTime = System.currentTimeMillis();
		System.out.println("Build CG cost：" + ((double) (endCGTime - startCGTime) / 1000) + " seconds");

		if (builder != null) {
			SLVAnalyzer pass = new SLVAnalyzer(builder, appPath);
			try {
				pass.analyze();
			} catch (IOException e) {
				e.printStackTrace();
			}
			System.out.println("<finish>");
		}

		long endTime = System.currentTimeMillis();
		System.out.println("Total cost：" + ((double) (endTime - startTime) / 1000) + " seconds");
	}
}