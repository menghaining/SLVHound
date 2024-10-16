/*
 * Copyright (c) 2002-2022, tianQi company. - All Rights Reserved
 */
package com.ibm.wala.classLoader;

import com.ibm.wala.shrikeCT.InvalidClassFileException;
import com.ibm.wala.util.shrike.ShrikeClassReaderHandle;
import com.ibm.wala.util.strings.ImmutableByteArray;

import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;

public class ClassURLModule extends AbstractURLModule implements SourceModule {
	private final String className;

	public ClassURLModule(URL url) throws InvalidClassFileException {
		super(url);
		ShrikeClassReaderHandle reader = new ShrikeClassReaderHandle(this);
		ImmutableByteArray name = ImmutableByteArray.make(reader.get().getName());
		className = name.toString();
	}

	@Override
	public String getClassName() {
		return className;
	}

	@Override
	public boolean isClassFile() {
		return true;
	}

	@Override
	public boolean isSourceFile() {
		return false;
	}

	@Override
	public Reader getInputReader() {
		return new InputStreamReader(getInputStream());
	}
}
