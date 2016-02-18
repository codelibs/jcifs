#!/bin/sh

JAVA_HOME=/usr/local/java5
CLASSPATH=../build:.
RUN="${JAVA_HOME}/bin/java -cp ${CLASSPATH}"

$RUN ClassLoaderTest file:/home/miallen/p/jcifs/jcifs-1.3.18.jar
