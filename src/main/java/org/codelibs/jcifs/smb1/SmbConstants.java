package org.codelibs.jcifs.smb1;

import java.net.InetAddress;
import java.util.LinkedList;
import java.util.TimeZone;

interface SmbConstants {

    /** Default SMB port number */
    int DEFAULT_PORT = 445;

    /** Default maximum multiplex count */
    int DEFAULT_MAX_MPX_COUNT = 10;
    /** Default response timeout in milliseconds */
    int DEFAULT_RESPONSE_TIMEOUT = 30000;
    /** Default socket timeout in milliseconds */
    int DEFAULT_SO_TIMEOUT = 35000;
    /** Default receive buffer size in bytes */
    int DEFAULT_RCV_BUF_SIZE = 60416;
    /** Default send buffer size in bytes */
    int DEFAULT_SND_BUF_SIZE = 16644;
    /** Default session limit */
    int DEFAULT_SSN_LIMIT = 250;
    /** Default connection timeout in milliseconds */
    int DEFAULT_CONN_TIMEOUT = 35000;

    /** Local address to bind to */
    InetAddress LADDR = Config.getLocalHost();
    /** Local port to bind to */
    int LPORT = Config.getInt("jcifs.client.lport", 0);
    /** Maximum multiplex count */
    int MAX_MPX_COUNT = Config.getInt("jcifs.client.maxMpxCount", DEFAULT_MAX_MPX_COUNT);
    /** Send buffer size in bytes */
    int SND_BUF_SIZE = Config.getInt("jcifs.client.snd_buf_size", DEFAULT_SND_BUF_SIZE);
    /** Receive buffer size in bytes */
    int RCV_BUF_SIZE = Config.getInt("jcifs.client.rcv_buf_size", DEFAULT_RCV_BUF_SIZE);
    /** Whether to use Unicode strings */
    boolean USE_UNICODE = Config.getBoolean("jcifs.client.useUnicode", true);
    /** Whether to force Unicode usage */
    boolean FORCE_UNICODE = Config.getBoolean("jcifs.client.useUnicode", false);
    /** Whether to use NT status codes */
    boolean USE_NTSTATUS = Config.getBoolean("jcifs.client.useNtStatus", true);
    /** Whether signing is preferred */
    boolean SIGNPREF = Config.getBoolean("jcifs.client.signingPreferred", false);
    /** Whether to use NT SMBs */
    boolean USE_NTSMBS = Config.getBoolean("jcifs.client.useNTSmbs", true);
    /** Whether to use extended security */
    boolean USE_EXTSEC = Config.getBoolean("jcifs.client.useExtendedSecurity", true);

    /** NetBIOS hostname */
    String NETBIOS_HOSTNAME = Config.getProperty("jcifs.netbios.hostname", null);
    /** LM compatibility level */
    int LM_COMPATIBILITY = Config.getInt("jcifs.lmCompatibility", 3);

    /** No flags set */
    int FLAGS_NONE = 0x00;
    /** Lock and read write and unlock flag */
    int FLAGS_LOCK_AND_READ_WRITE_AND_UNLOCK = 0x01;
    /** Receive buffer posted flag */
    int FLAGS_RECEIVE_BUFFER_POSTED = 0x02;
    /** Path names are caseless flag */
    int FLAGS_PATH_NAMES_CASELESS = 0x08;
    /** Path names canonicalized flag */
    int FLAGS_PATH_NAMES_CANONICALIZED = 0x10;
    /** Oplock requested or granted flag */
    int FLAGS_OPLOCK_REQUESTED_OR_GRANTED = 0x20;
    /** Notify of modify action flag */
    int FLAGS_NOTIFY_OF_MODIFY_ACTION = 0x40;
    /** Response flag */
    int FLAGS_RESPONSE = 0x80;

    /** No flags2 set */
    int FLAGS2_NONE = 0x0000;
    /** Long filenames supported flag */
    int FLAGS2_LONG_FILENAMES = 0x0001;
    /** Extended attributes supported flag */
    int FLAGS2_EXTENDED_ATTRIBUTES = 0x0002;
    /** Security signatures supported flag */
    int FLAGS2_SECURITY_SIGNATURES = 0x0004;
    /** Extended security negotiation flag */
    int FLAGS2_EXTENDED_SECURITY_NEGOTIATION = 0x0800;
    /** Resolve paths in DFS flag */
    int FLAGS2_RESOLVE_PATHS_IN_DFS = 0x1000;
    /** Permit read if execute permission flag */
    int FLAGS2_PERMIT_READ_IF_EXECUTE_PERM = 0x2000;
    /** 32-bit status codes flag */
    int FLAGS2_STATUS32 = 0x4000;
    /** Unicode strings flag */
    int FLAGS2_UNICODE = 0x8000;

    /** No capabilities */
    int CAP_NONE = 0x0000;
    /** Raw mode capability */
    int CAP_RAW_MODE = 0x0001;
    /** MPX mode capability */
    int CAP_MPX_MODE = 0x0002;
    /** Unicode capability */
    int CAP_UNICODE = 0x0004;
    /** Large files capability */
    int CAP_LARGE_FILES = 0x0008;
    /** NT SMBs capability */
    int CAP_NT_SMBS = 0x0010;
    /** RPC remote APIs capability */
    int CAP_RPC_REMOTE_APIS = 0x0020;
    /** 32-bit status codes capability */
    int CAP_STATUS32 = 0x0040;
    /** Level II oplocks capability */
    int CAP_LEVEL_II_OPLOCKS = 0x0080;
    /** Lock and read capability */
    int CAP_LOCK_AND_READ = 0x0100;
    /** NT find capability */
    int CAP_NT_FIND = 0x0200;
    /** DFS capability */
    int CAP_DFS = 0x1000;
    /** Extended security capability */
    int CAP_EXTENDED_SECURITY = 0x80000000;

    // file attribute encoding
    /** Read-only file attribute */
    int ATTR_READONLY = 0x01;
    /** Hidden file attribute */
    int ATTR_HIDDEN = 0x02;
    /** System file attribute */
    int ATTR_SYSTEM = 0x04;
    /** Volume label attribute */
    int ATTR_VOLUME = 0x08;
    /** Directory attribute */
    int ATTR_DIRECTORY = 0x10;
    /** Archive attribute */
    int ATTR_ARCHIVE = 0x20;

    // extended file attribute encoding(others same as above)
    /** Compressed file attribute */
    int ATTR_COMPRESSED = 0x800;
    /** Normal file attribute */
    int ATTR_NORMAL = 0x080;
    /** Temporary file attribute */
    int ATTR_TEMPORARY = 0x100;

    // access mask encoding
    /** File read data access right */
    int FILE_READ_DATA = 0x00000001; // 1
    /** File write data access right */
    int FILE_WRITE_DATA = 0x00000002; // 2
    /** File append data access right */
    int FILE_APPEND_DATA = 0x00000004; // 3
    /** File read extended attributes access right */
    int FILE_READ_EA = 0x00000008; // 4
    /** File write extended attributes access right */
    int FILE_WRITE_EA = 0x00000010; // 5
    /** File execute access right */
    int FILE_EXECUTE = 0x00000020; // 6
    /** File delete child access right */
    int FILE_DELETE = 0x00000040; // 7
    /** File read attributes access right */
    int FILE_READ_ATTRIBUTES = 0x00000080; // 8
    /** File write attributes access right */
    int FILE_WRITE_ATTRIBUTES = 0x00000100; // 9
    /** Delete access right */
    int DELETE = 0x00010000; // 16
    /** Read control access right */
    int READ_CONTROL = 0x00020000; // 17
    /** Write DAC access right */
    int WRITE_DAC = 0x00040000; // 18
    /** Write owner access right */
    int WRITE_OWNER = 0x00080000; // 19
    /** Synchronize access right */
    int SYNCHRONIZE = 0x00100000; // 20
    /** Generic all access right */
    int GENERIC_ALL = 0x10000000; // 28
    /** Generic execute access right */
    int GENERIC_EXECUTE = 0x20000000; // 29
    /** Generic write access right */
    int GENERIC_WRITE = 0x40000000; // 30
    /** Generic read access right */
    int GENERIC_READ = 0x80000000; // 31

    // flags for move and copy
    /** Target must be file flag */
    int FLAGS_TARGET_MUST_BE_FILE = 0x0001;
    /** Target must be directory flag */
    int FLAGS_TARGET_MUST_BE_DIRECTORY = 0x0002;
    /** Copy target mode ASCII flag */
    int FLAGS_COPY_TARGET_MODE_ASCII = 0x0004;
    /** Copy source mode ASCII flag */
    int FLAGS_COPY_SOURCE_MODE_ASCII = 0x0008;
    /** Verify all writes flag */
    int FLAGS_VERIFY_ALL_WRITES = 0x0010;
    /** Tree copy flag */
    int FLAGS_TREE_COPY = 0x0020;

    // open function
    /** Open function fail if exists */
    int OPEN_FUNCTION_FAIL_IF_EXISTS = 0x0000;
    /** Open function overwrite if exists */
    int OPEN_FUNCTION_OVERWRITE_IF_EXISTS = 0x0020;

    /** Process ID */
    int PID = (int) (Math.random() * 65536d);

    /** Share level security */
    int SECURITY_SHARE = 0x00;
    /** User level security */
    int SECURITY_USER = 0x01;

    /** Command offset in SMB header */
    int CMD_OFFSET = 4;
    /** Error code offset in SMB header */
    int ERROR_CODE_OFFSET = 5;
    /** Flags offset in SMB header */
    int FLAGS_OFFSET = 9;
    /** Signature offset in SMB header */
    int SIGNATURE_OFFSET = 14;
    /** TID offset in SMB header */
    int TID_OFFSET = 24;
    /** SMB header length */
    int HEADER_LENGTH = 32;

    /** Milliseconds between 1970 and 1601 */
    long MILLISECONDS_BETWEEN_1970_AND_1601 = 11644473600000L;
    /** Default timezone */
    TimeZone TZ = TimeZone.getDefault();

    /** Whether to use batching */
    boolean USE_BATCHING = Config.getBoolean("jcifs.client.useBatching", true);
    /** OEM encoding */
    String OEM_ENCODING = Config.getProperty("jcifs.encoding", Config.DEFAULT_OEM_ENCODING);
    /** Unicode encoding */
    String UNI_ENCODING = "UTF-16LE";
    /** Default FLAGS2 value */
    int DEFAULT_FLAGS2 = FLAGS2_LONG_FILENAMES | FLAGS2_EXTENDED_ATTRIBUTES | (USE_EXTSEC ? FLAGS2_EXTENDED_SECURITY_NEGOTIATION : 0)
            | (SIGNPREF ? FLAGS2_SECURITY_SIGNATURES : 0) | (USE_NTSTATUS ? FLAGS2_STATUS32 : 0) | (USE_UNICODE ? FLAGS2_UNICODE : 0);
    /** Default capabilities */
    int DEFAULT_CAPABILITIES =
            (USE_NTSMBS ? CAP_NT_SMBS : 0) | (USE_NTSTATUS ? CAP_STATUS32 : 0) | (USE_UNICODE ? CAP_UNICODE : 0) | CAP_DFS;
    /** FLAGS2 value */
    int FLAGS2 = Config.getInt("jcifs.client.flags2", DEFAULT_FLAGS2);
    /** Capabilities value */
    int CAPABILITIES = Config.getInt("jcifs.client.capabilities", DEFAULT_CAPABILITIES);
    /** Whether to use TCP_NODELAY */
    boolean TCP_NODELAY = Config.getBoolean("jcifs.client.tcpNoDelay", false);
    /** Response timeout in milliseconds */
    int RESPONSE_TIMEOUT = Config.getInt("jcifs.client.responseTimeout", DEFAULT_RESPONSE_TIMEOUT);

    /** List of active connections */
    LinkedList CONNECTIONS = new LinkedList();

    /** Session limit */
    int SSN_LIMIT = Config.getInt("jcifs.client.ssnLimit", DEFAULT_SSN_LIMIT);
    /** Socket timeout in milliseconds */
    int SO_TIMEOUT = Config.getInt("jcifs.client.soTimeout", DEFAULT_SO_TIMEOUT);
    /** Connection timeout in milliseconds */
    int CONN_TIMEOUT = Config.getInt("jcifs.client.connTimeout", DEFAULT_CONN_TIMEOUT);
    /** Native operating system name */
    String NATIVE_OS = Config.getProperty("jcifs.client.nativeOs", System.getProperty("os.name"));
    /** Native LAN manager name */
    String NATIVE_LANMAN = Config.getProperty("jcifs.client.nativeLanMan", "jCIFS");
    /** Virtual circuit number */
    int VC_NUMBER = 1;
    /** Null transport instance */
    SmbTransport NULL_TRANSPORT = new SmbTransport(null, 0, null, 0);
}
