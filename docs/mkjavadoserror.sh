#!/bin/sh

./csvprint -f -s '\t' doserror.txt "	public static final int %5 = %3;\n"
echo
./csvprint -f -s '\t' doserror.txt "		%5,\n"
echo
./csvprint -f -s '\t' doserror.txt "		\"%5\",\n"
echo
./csvprint -f -s '\t' doserror.txt "		\"%6\",\n"
echo
./csvprint -f -s '\t' doserror.txt "		{ %3, %4 },\n"
