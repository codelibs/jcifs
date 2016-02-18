#!/bin/sh

JAVA_HOME=/usr/local/java
CLASSPATH=../build:.
PROPERTIES=../../user10.prp
RUN="${JAVA_HOME}/bin/java -cp ${CLASSPATH} -Djcifs.properties=${PROPERTIES}"

SERVER=dc1.w.net
SHARE=tmp
WRITE_DIR=test/
SRC_DIR=test/Junk
FILE1=test/Junk/10883563.doc

URL_SERVER=smb://${SERVER}/
URL_SHARE=${URL_SERVER}${SHARE}/
URL_WRITE_DIR=${URL_SHARE}${WRITE_DIR}

[ "$1" = "ListACL" ] && $RUN ListACL ${URL_WRITE_DIR}
[ "$1" = "LargeListFiles" ] && $RUN LargeListFiles ${URL_WRITE_DIR}
[ "$1" = "CountPerms" ] && $RUN CountPerms ${URL_WRITE_DIR} 100
[ "$1" = "AclCrawler" ] && $RUN AclCrawler ${URL_WRITE_DIR} 100
[ "$1" = "SidCacheTest" ] && $RUN SidCacheTest ${URL_WRITE_DIR}
[ "$1" = "GetSecurity" ] && $RUN GetSecurity ${URL_WRITE_DIR}
[ "$1" = "GetSecurityS" ] && $RUN GetSecurity ${URL_SHARE}
[ "$1" = "GetShareSecurity" ] && $RUN GetShareSecurity ${URL_WRITE_DIR}
[ "$1" = "SidCrawler" ] && $RUN SidCrawler ${URL_WRITE_DIR} 5
[ "$1" = "GetGroupMemberSidsFromURL" ] && $RUN GetGroupMemberSidsFromURL ${URL_WRITE_DIR}
[ "$1" = "InterruptTest" ] && $RUN InterruptTest ${URL_WRITE_DIR}Append.txt
[ "$1" = "AllocInfo" ] && $RUN AllocInfo ${URL_SHARE}
[ "$1" = "Append" ] && $RUN Append ${URL_WRITE_DIR}Append.txt
[ "$1" = "AuthListFiles" ] && $RUN AuthListFiles smb://bogus\@${SERVER}/${SHARE}/
[ "$1" = "CopyTo" ] && $RUN CopyTo ${URL_SHARE}${SRC_DIR}/ ${URL_SHARE}${WRITE_DIR}CopyTo/
[ "$1" = "CreateFile" ] && $RUN CreateFile ${URL_WRITE_DIR}CreateFile.txt
[ "$1" = "Delete" ] && $RUN Delete ${URL_WRITE_DIR}CreateFile.txt
[ "$1" = "Equals" ] && $RUN Equals ${URL_WRITE_DIR}CreateFile.txt ${URL_SHARE}${WRITE_DIR}../${WRITE_DIR}CreateFile.txt
[ "$1" = "Exists" ] && $RUN Exists ${URL_WRITE_DIR}
[ "$1" = "FileInfo" ] && $RUN FileInfo ${URL_SHARE}${FILE1} 0
[ "$1" = "FileOps" ] && $RUN FileOps ${URL_WRITE_DIR}
[ "$1" = "FilterFiles" ] && $RUN FilterFiles ${URL_SHARE}${SRC_DIR}/
[ "$1" = "GetDate" ] && $RUN GetDate ${URL_SHARE}${FILE1}
[ "$1" = "Get" ] && $RUN Get ${URL_SHARE}test/Makefile.txt
[ "$1" = "GetType" ] && $RUN GetType ${URL_SHARE}
[ "$1" = "GrowWrite" ] && $RUN GrowWrite ${URL_WRITE_DIR}GrowWrite.txt
[ "$1" = "GetURL" ] && $RUN GetURL ${URL_WRITE_DIR}Append.txt
[ "$1" = "HttpURL" ] && $RUN HttpURL ${URL_WRITE_DIR} ../Append.txt
[ "$1" = "Interleave" ] && $RUN Interleave ${URL_WRITE_DIR} 25
[ "$1" = "IsDir" ] && $RUN IsDir ${URL_SHARE}${SRC_DIR}/
[ "$1" = "Length" ] && $RUN Length ${URL_SHARE}${FILE1}
[ "$1" = "ListFiles" ] && $RUN ListFiles ${URL_WRITE_DIR}
[ "$1" = "ListShares" ] && $RUN ListFiles ${URL_SERVER}
[ "$1" = "List" ] && $RUN List ${URL_WRITE_DIR}
[ "$1" = "ListTypes" ] && $RUN ListTypes ${URL_WRITE_DIR}
[ "$1" = "Mkdir" ] && $RUN Mkdir ${URL_WRITE_DIR}Mkdir
[ "$1" = "NodeStatus" ] && $RUN NodeStatus ${SERVER}
[ "$1" = "Put" ] && $RUN Put ${URL_WRITE_DIR}Makefile
[ "$1" = "Query" ] && $RUN Query ${SERVER}
[ "$1" = "RenameTo" ] && $RUN RenameTo ${URL_WRITE_DIR}Makefile ${URL_WRITE_DIR}Makefile.txt
[ "$1" = "SetAttrs" ] && $RUN SetAttrs ${URL_WRITE_DIR}Makefile.txt FFFF
[ "$1" = "SetTime" ] && $RUN SetTime ${URL_WRITE_DIR}Makefile.txt
[ "$1" = "SlowWrite" ] && $RUN SlowWrite ${URL_WRITE_DIR}SlowWrite.txt
[ "$1" = "SlowRead" ] && $RUN SlowRead ${URL_WRITE_DIR}SlowWrite.txt
[ "$1" = "SmbCrawler" ] && $RUN SmbCrawler ${URL_WRITE_DIR} 1000
[ "$1" = "T2Crawler" ] && $RUN T2Crawler ${URL_WRITE_DIR} 3 1000
[ "$1" = "TestRandomAccess1" ] && $RUN TestRandomAccess ${URL_WRITE_DIR}TestRandomAccess.bin 1
[ "$1" = "TestRandomAccess2" ] && $RUN TestRandomAccess ${URL_WRITE_DIR}TestRandomAccess.bin 2 0
[ "$1" = "TestRandomAccess3" ] && $RUN TestRandomAccess ${URL_WRITE_DIR}TestRandomAccess.bin 3 1234


