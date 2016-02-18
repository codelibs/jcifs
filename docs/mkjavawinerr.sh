#!/bin/sh

./csvprint -f -s '\t' winerr.txt "	public static final int %2 = %1;\n"
echo
echo "	static final int[] WINERR_CODES = {"
./csvprint -f -s '\t' winerr.txt "		%2,\n"
echo "	};"
echo
echo "	static final String[] WINERR_MESSAGES = {"
./csvprint -f -s '\t' winerr.txt "		\"%3\",\n"
echo "	};"

