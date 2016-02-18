JAVA_HOME=/usr/local/java5
CLASSPATH=../build:.

.SUFFIXES: .java .class

CLASSFILES=TestListLoop.class TestGetParent.class SidLookup.class GetGroupMemberSidsFromURL.class ListACL.class LargeListFiles.class GetShareSecurity.class CountPerms.class AclCrawler.class SidCacheTest.class GetSecurity.class SidCrawler.class InterruptTest.class AllocInfo.class Append.class AuthListFiles.class CallNamedPipe.class CopyTo.class CreateFile.class Delete.class Equals.class Exists.class FileInfo.class FileOps.class FilterFiles.class GetDate.class GetDfsPath.class Get.class GetType.class GetURL.class GrowWrite.class HttpURL.class Interleave.class IsDir.class Length.class ListFiles.class List.class ListTypes.class Mkdir.class NodeStatus.class OpenExclusive.class PeekNamedPipe.class PipeTalk.class Put.class Query.class RenameTo.class SetAttrs.class SetTime.class SlowRead.class SlowWrite.class SmbCrawler.class SmbTableFile.class SmbTableFileRecord.class T2Crawler.class TestRandomAccess.class TestSmbURL.class TestUnicode.class ThreadedNbtQuery.class ThreadedSmbCrawler.class ThreadedUniQuery.class Torture1.class Torture2.class TortureTest5.class TransactNamedPipe.class URLTest.class VerifyGuest.class VerifyIO.class VerifyReads.class

all: ${CLASSFILES}

.java.class:
	${JAVA_HOME}/bin/javac -classpath ${CLASSPATH} $<

clean:
	${RM} *.class
