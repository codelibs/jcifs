#!/bin/sh

csvprint -f -s ' ' ntstatus.txt "	public static final int %3 = %1;\n"
echo
echo "	static final int[] NT_STATUS_CODES = {"
csvprint -f -s ' ' ntstatus.txt "		%3,\n"
echo "	};"
echo
echo "	static final String[] NT_STATUS_MESSAGES = {"
csvprint -f -s ' ' ntstatus.txt "		\"%4\",\n"
echo "	};"

