package jcifs.smb1.smb1;

import java.net.InetAddress;
import java.util.LinkedList;
import java.util.TimeZone;

import jcifs.smb1.Config;

interface SmbConstants {

    int DEFAULT_PORT = 445;

    int DEFAULT_MAX_MPX_COUNT = 10;
    int DEFAULT_RESPONSE_TIMEOUT = 30000;
    int DEFAULT_SO_TIMEOUT = 35000;
    int DEFAULT_RCV_BUF_SIZE = 60416;
    int DEFAULT_SND_BUF_SIZE = 16644;
    int DEFAULT_SSN_LIMIT = 250;
    int DEFAULT_CONN_TIMEOUT = 35000;

    InetAddress LADDR = Config.getLocalHost();
    int LPORT = Config.getInt("jcifs.smb1.smb.client.lport", 0);
    int MAX_MPX_COUNT = Config.getInt("jcifs.smb1.smb.client.maxMpxCount", DEFAULT_MAX_MPX_COUNT);
    int SND_BUF_SIZE = Config.getInt("jcifs.smb1.smb.client.snd_buf_size", DEFAULT_SND_BUF_SIZE);
    int RCV_BUF_SIZE = Config.getInt("jcifs.smb1.smb.client.rcv_buf_size", DEFAULT_RCV_BUF_SIZE);
    boolean USE_UNICODE = Config.getBoolean("jcifs.smb1.smb.client.useUnicode", true);
    boolean FORCE_UNICODE = Config.getBoolean("jcifs.smb1.smb.client.useUnicode", false);
    boolean USE_NTSTATUS = Config.getBoolean("jcifs.smb1.smb.client.useNtStatus", true);
    boolean SIGNPREF = Config.getBoolean("jcifs.smb1.smb.client.signingPreferred", false);
    boolean USE_NTSMBS = Config.getBoolean("jcifs.smb1.smb.client.useNTSmbs", true);
    boolean USE_EXTSEC = Config.getBoolean("jcifs.smb1.smb.client.useExtendedSecurity", true);

    String NETBIOS_HOSTNAME = Config.getProperty("jcifs.smb1.netbios.hostname", null);
    int LM_COMPATIBILITY = Config.getInt("jcifs.smb1.smb.lmCompatibility", 3);

    int FLAGS_NONE = 0x00;
    int FLAGS_LOCK_AND_READ_WRITE_AND_UNLOCK = 0x01;
    int FLAGS_RECEIVE_BUFFER_POSTED = 0x02;
    int FLAGS_PATH_NAMES_CASELESS = 0x08;
    int FLAGS_PATH_NAMES_CANONICALIZED = 0x10;
    int FLAGS_OPLOCK_REQUESTED_OR_GRANTED = 0x20;
    int FLAGS_NOTIFY_OF_MODIFY_ACTION = 0x40;
    int FLAGS_RESPONSE = 0x80;

    int FLAGS2_NONE = 0x0000;
    int FLAGS2_LONG_FILENAMES = 0x0001;
    int FLAGS2_EXTENDED_ATTRIBUTES = 0x0002;
    int FLAGS2_SECURITY_SIGNATURES = 0x0004;
    int FLAGS2_EXTENDED_SECURITY_NEGOTIATION = 0x0800;
    int FLAGS2_RESOLVE_PATHS_IN_DFS = 0x1000;
    int FLAGS2_PERMIT_READ_IF_EXECUTE_PERM = 0x2000;
    int FLAGS2_STATUS32 = 0x4000;
    int FLAGS2_UNICODE = 0x8000;

    int CAP_NONE = 0x0000;
    int CAP_RAW_MODE = 0x0001;
    int CAP_MPX_MODE = 0x0002;
    int CAP_UNICODE = 0x0004;
    int CAP_LARGE_FILES = 0x0008;
    int CAP_NT_SMBS = 0x0010;
    int CAP_RPC_REMOTE_APIS = 0x0020;
    int CAP_STATUS32 = 0x0040;
    int CAP_LEVEL_II_OPLOCKS = 0x0080;
    int CAP_LOCK_AND_READ = 0x0100;
    int CAP_NT_FIND = 0x0200;
    int CAP_DFS = 0x1000;
    int CAP_EXTENDED_SECURITY = 0x80000000;

    // file attribute encoding
    int ATTR_READONLY = 0x01;
    int ATTR_HIDDEN = 0x02;
    int ATTR_SYSTEM = 0x04;
    int ATTR_VOLUME = 0x08;
    int ATTR_DIRECTORY = 0x10;
    int ATTR_ARCHIVE = 0x20;

    // extended file attribute encoding(others same as above)
    int ATTR_COMPRESSED = 0x800;
    int ATTR_NORMAL = 0x080;
    int ATTR_TEMPORARY = 0x100;

    // access mask encoding
    int FILE_READ_DATA = 0x00000001; // 1
    int FILE_WRITE_DATA = 0x00000002; // 2
    int FILE_APPEND_DATA = 0x00000004; // 3
    int FILE_READ_EA = 0x00000008; // 4
    int FILE_WRITE_EA = 0x00000010; // 5
    int FILE_EXECUTE = 0x00000020; // 6
    int FILE_DELETE = 0x00000040; // 7
    int FILE_READ_ATTRIBUTES = 0x00000080; // 8
    int FILE_WRITE_ATTRIBUTES = 0x00000100; // 9
    int DELETE = 0x00010000; // 16
    int READ_CONTROL = 0x00020000; // 17
    int WRITE_DAC = 0x00040000; // 18
    int WRITE_OWNER = 0x00080000; // 19
    int SYNCHRONIZE = 0x00100000; // 20
    int GENERIC_ALL = 0x10000000; // 28
    int GENERIC_EXECUTE = 0x20000000; // 29
    int GENERIC_WRITE = 0x40000000; // 30
    int GENERIC_READ = 0x80000000; // 31

    // flags for move and copy
    int FLAGS_TARGET_MUST_BE_FILE = 0x0001;
    int FLAGS_TARGET_MUST_BE_DIRECTORY = 0x0002;
    int FLAGS_COPY_TARGET_MODE_ASCII = 0x0004;
    int FLAGS_COPY_SOURCE_MODE_ASCII = 0x0008;
    int FLAGS_VERIFY_ALL_WRITES = 0x0010;
    int FLAGS_TREE_COPY = 0x0020;

    // open function
    int OPEN_FUNCTION_FAIL_IF_EXISTS = 0x0000;
    int OPEN_FUNCTION_OVERWRITE_IF_EXISTS = 0x0020;

    int PID = (int) (Math.random() * 65536d);

    int SECURITY_SHARE = 0x00;
    int SECURITY_USER = 0x01;

    int CMD_OFFSET = 4;
    int ERROR_CODE_OFFSET = 5;
    int FLAGS_OFFSET = 9;
    int SIGNATURE_OFFSET = 14;
    int TID_OFFSET = 24;
    int HEADER_LENGTH = 32;

    long MILLISECONDS_BETWEEN_1970_AND_1601 = 11644473600000L;
    TimeZone TZ = TimeZone.getDefault();

    boolean USE_BATCHING = Config.getBoolean("jcifs.smb1.smb.client.useBatching", true);
    String OEM_ENCODING = Config.getProperty("jcifs.smb1.encoding", Config.DEFAULT_OEM_ENCODING);
    String UNI_ENCODING = "UTF-16LE";
    int DEFAULT_FLAGS2 = FLAGS2_LONG_FILENAMES | FLAGS2_EXTENDED_ATTRIBUTES | (USE_EXTSEC ? FLAGS2_EXTENDED_SECURITY_NEGOTIATION : 0)
            | (SIGNPREF ? FLAGS2_SECURITY_SIGNATURES : 0) | (USE_NTSTATUS ? FLAGS2_STATUS32 : 0) | (USE_UNICODE ? FLAGS2_UNICODE : 0);
    int DEFAULT_CAPABILITIES =
            (USE_NTSMBS ? CAP_NT_SMBS : 0) | (USE_NTSTATUS ? CAP_STATUS32 : 0) | (USE_UNICODE ? CAP_UNICODE : 0) | CAP_DFS;
    int FLAGS2 = Config.getInt("jcifs.smb1.smb.client.flags2", DEFAULT_FLAGS2);
    int CAPABILITIES = Config.getInt("jcifs.smb1.smb.client.capabilities", DEFAULT_CAPABILITIES);
    boolean TCP_NODELAY = Config.getBoolean("jcifs.smb1.smb.client.tcpNoDelay", false);
    int RESPONSE_TIMEOUT = Config.getInt("jcifs.smb1.smb.client.responseTimeout", DEFAULT_RESPONSE_TIMEOUT);

    LinkedList CONNECTIONS = new LinkedList();

    int SSN_LIMIT = Config.getInt("jcifs.smb1.smb.client.ssnLimit", DEFAULT_SSN_LIMIT);
    int SO_TIMEOUT = Config.getInt("jcifs.smb1.smb.client.soTimeout", DEFAULT_SO_TIMEOUT);
    int CONN_TIMEOUT = Config.getInt("jcifs.smb1.smb.client.connTimeout", DEFAULT_CONN_TIMEOUT);
    String NATIVE_OS = Config.getProperty("jcifs.smb1.smb.client.nativeOs", System.getProperty("os.name"));
    String NATIVE_LANMAN = Config.getProperty("jcifs.smb1.smb.client.nativeLanMan", "jCIFS");
    int VC_NUMBER = 1;
    SmbTransport NULL_TRANSPORT = new SmbTransport(null, 0, null, 0);
}
