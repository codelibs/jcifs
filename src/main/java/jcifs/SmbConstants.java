/*
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package jcifs;

/**
 * Utility class holding several protocol constrants
 *
 * @author mbechler
 *
 *
 * <p>This interface is intended for internal use.</p>
 */
public interface SmbConstants {

    /**
     * Default SMB port number for direct TCP transport.
     */
    int DEFAULT_PORT = 445;

    /**
     * Default maximum number of outstanding SMB requests.
     */
    int DEFAULT_MAX_MPX_COUNT = 10;
    /**
     * Default timeout in milliseconds for SMB responses.
     */
    int DEFAULT_RESPONSE_TIMEOUT = 30000;
    /**
     * Default socket timeout in milliseconds.
     */
    int DEFAULT_SO_TIMEOUT = 35000;
    /**
     * Default receive buffer size for SMB transport.
     */
    int DEFAULT_RCV_BUF_SIZE = 0xFFFF;
    /**
     * Default send buffer size for SMB transport.
     */
    int DEFAULT_SND_BUF_SIZE = 0xFFFF;
    /**
     * Default buffer size for change notification responses.
     */
    int DEFAULT_NOTIFY_BUF_SIZE = 1024;

    /**
     * Default maximum number of sessions per transport connection.
     */
    int DEFAULT_SSN_LIMIT = 250;
    /**
     * Default connection timeout in milliseconds.
     */
    int DEFAULT_CONN_TIMEOUT = 35000;

    /**
     * No flags set in SMB header.
     */
    int FLAGS_NONE = 0x00;
    /**
     * Obsolete lock and read/write and unlock flag.
     */
    int FLAGS_LOCK_AND_READ_WRITE_AND_UNLOCK = 0x01;
    /**
     * Receive buffer has been posted flag.
     */
    int FLAGS_RECEIVE_BUFFER_POSTED = 0x02;
    /**
     * Path names are case-insensitive flag.
     */
    int FLAGS_PATH_NAMES_CASELESS = 0x08;
    /**
     * Path names are canonicalized flag.
     */
    int FLAGS_PATH_NAMES_CANONICALIZED = 0x10;
    /**
     * Opportunistic lock requested or granted flag.
     */
    int FLAGS_OPLOCK_REQUESTED_OR_GRANTED = 0x20;
    /**
     * Notify client of any action which modified the file flag.
     */
    int FLAGS_NOTIFY_OF_MODIFY_ACTION = 0x40;
    /**
     * Message is a response from server flag.
     */
    int FLAGS_RESPONSE = 0x80;

    /**
     * No flags2 set in SMB header.
     */
    int FLAGS2_NONE = 0x0000;
    /**
     * Long file names are supported flag.
     */
    int FLAGS2_LONG_FILENAMES = 0x0001;
    /**
     * Extended attributes are supported flag.
     */
    int FLAGS2_EXTENDED_ATTRIBUTES = 0x0002;
    /**
     * Security signatures are supported flag.
     */
    int FLAGS2_SECURITY_SIGNATURES = 0x0004;
    /**
     * Security signatures are required flag.
     */
    int FLAGS2_SECURITY_REQUIRE_SIGNATURES = 0x0010;
    /**
     * Extended security negotiation is supported flag.
     */
    int FLAGS2_EXTENDED_SECURITY_NEGOTIATION = 0x0800;
    /**
     * Resolve paths in Distributed File System flag.
     */
    int FLAGS2_RESOLVE_PATHS_IN_DFS = 0x1000;
    /**
     * Permit read if execute permission flag.
     */
    int FLAGS2_PERMIT_READ_IF_EXECUTE_PERM = 0x2000;
    /**
     * Use 32-bit status codes flag.
     */
    int FLAGS2_STATUS32 = 0x4000;
    /**
     * Strings are Unicode flag.
     */
    int FLAGS2_UNICODE = 0x8000;

    /**
     * No capabilities.
     */
    int CAP_NONE = 0x0000;
    /**
     * Raw mode transfers are supported capability.
     */
    int CAP_RAW_MODE = 0x0001;
    /**
     * Multiplex mode is supported capability.
     */
    int CAP_MPX_MODE = 0x0002;
    /**
     * Unicode strings are supported capability.
     */
    int CAP_UNICODE = 0x0004;
    /**
     * Large files are supported capability.
     */
    int CAP_LARGE_FILES = 0x0008;
    /**
     * NT SMBs are supported capability.
     */
    int CAP_NT_SMBS = 0x0010;
    /**
     * RPC remote APIs are supported capability.
     */
    int CAP_RPC_REMOTE_APIS = 0x0020;
    /**
     * NT status codes are supported capability.
     */
    int CAP_STATUS32 = 0x0040;
    /**
     * Level II oplocks are supported capability.
     */
    int CAP_LEVEL_II_OPLOCKS = 0x0080;
    /**
     * Lock and read operation is supported capability.
     */
    int CAP_LOCK_AND_READ = 0x0100;
    /**
     * NT find operations are supported capability.
     */
    int CAP_NT_FIND = 0x0200;
    /**
     * DFS operations are supported capability.
     */
    int CAP_DFS = 0x1000;
    /**
     * Large read operations are supported capability.
     */
    int CAP_LARGE_READX = 0x4000;
    /**
     * Large write operations are supported capability.
     */
    int CAP_LARGE_WRITEX = 0x8000;
    /**
     * Extended security exchanges are supported capability.
     */
    int CAP_EXTENDED_SECURITY = 0x80000000;

    // file attribute encoding
    /**
     * File is marked read-only
     */
    int ATTR_READONLY = 0x01;
    /**
     * File is marked hidden
     */
    int ATTR_HIDDEN = 0x02;
    /**
     * File is marked a system file
     */
    int ATTR_SYSTEM = 0x04;
    /**
     * File is marked a volume
     */
    int ATTR_VOLUME = 0x08;
    /**
     * File is a directory
     */
    int ATTR_DIRECTORY = 0x10;

    /**
     * Files is marked to be archived
     */
    int ATTR_ARCHIVE = 0x20;

    // extended file attribute encoding(others same as above)
    /**
     * File is compressed.
     */
    int ATTR_COMPRESSED = 0x800;
    /**
     * File is a normal file.
     */
    int ATTR_NORMAL = 0x080;
    /**
     * File is temporary.
     */
    int ATTR_TEMPORARY = 0x100;

    // access mask encoding
    /**
     * Permission to read data from the file.
     */
    int FILE_READ_DATA = 0x00000001; // 1
    /**
     * Permission to write data to the file.
     */
    int FILE_WRITE_DATA = 0x00000002; // 2
    /**
     * Permission to append data to the file.
     */
    int FILE_APPEND_DATA = 0x00000004; // 3
    /**
     * Permission to read extended attributes.
     */
    int FILE_READ_EA = 0x00000008; // 4
    /**
     * Permission to write extended attributes.
     */
    int FILE_WRITE_EA = 0x00000010; // 5
    /**
     * Permission to execute the file.
     */
    int FILE_EXECUTE = 0x00000020; // 6
    /**
     * Permission to delete the file.
     */
    int FILE_DELETE = 0x00000040; // 7
    /**
     * Permission to read file attributes.
     */
    int FILE_READ_ATTRIBUTES = 0x00000080; // 8
    /**
     * Permission to write file attributes.
     */
    int FILE_WRITE_ATTRIBUTES = 0x00000100; // 9
    /**
     * Permission to delete the object.
     */
    int DELETE = 0x00010000; // 16
    /**
     * Permission to read the security descriptor.
     */
    int READ_CONTROL = 0x00020000; // 17
    /**
     * Permission to write the discretionary access control list.
     */
    int WRITE_DAC = 0x00040000; // 18
    /**
     * Permission to change the owner.
     */
    int WRITE_OWNER = 0x00080000; // 19
    /**
     * Permission to synchronize.
     */
    int SYNCHRONIZE = 0x00100000; // 20
    /**
     * All generic permissions.
     */
    int GENERIC_ALL = 0x10000000; // 28
    /**
     * Generic execute permission.
     */
    int GENERIC_EXECUTE = 0x20000000; // 29
    /**
     * Generic write permission.
     */
    int GENERIC_WRITE = 0x40000000; // 30
    /**
     * Generic read permission.
     */
    int GENERIC_READ = 0x80000000; // 31

    // flags for move and copy
    /**
     * Target must be a file flag.
     */
    int FLAGS_TARGET_MUST_BE_FILE = 0x0001;
    /**
     * Target must be a directory flag.
     */
    int FLAGS_TARGET_MUST_BE_DIRECTORY = 0x0002;
    /**
     * Copy target in ASCII mode flag.
     */
    int FLAGS_COPY_TARGET_MODE_ASCII = 0x0004;
    /**
     * Copy source in ASCII mode flag.
     */
    int FLAGS_COPY_SOURCE_MODE_ASCII = 0x0008;
    /**
     * Verify all write operations flag.
     */
    int FLAGS_VERIFY_ALL_WRITES = 0x0010;
    /**
     * Copy entire tree flag.
     */
    int FLAGS_TREE_COPY = 0x0020;

    // open function
    /**
     * Open function to fail if file exists.
     */
    int OPEN_FUNCTION_FAIL_IF_EXISTS = 0x0000;
    /**
     * Open function to overwrite if file exists.
     */
    int OPEN_FUNCTION_OVERWRITE_IF_EXISTS = 0x0020;

    /**
     * Share level security mode.
     */
    int SECURITY_SHARE = 0x00;
    /**
     * User level security mode.
     */
    int SECURITY_USER = 0x01;

    /**
     * Offset of command field in SMB header.
     */
    int CMD_OFFSET = 4;
    /**
     * Offset of error code field in SMB header.
     */
    int ERROR_CODE_OFFSET = 5;
    /**
     * Offset of flags field in SMB header.
     */
    int FLAGS_OFFSET = 9;
    /**
     * Offset of signature field in SMB header.
     */
    int SIGNATURE_OFFSET = 14;
    /**
     * Offset of tree ID field in SMB header.
     */
    int TID_OFFSET = 24;
    /**
     * Length of SMB1 header in bytes.
     */
    int SMB1_HEADER_LENGTH = 32;

    /**
     * Milliseconds between January 1, 1970 and January 1, 1601.
     */
    long MILLISECONDS_BETWEEN_1970_AND_1601 = 11644473600000L;

    /**
     * Default OEM encoding for non-Unicode strings.
     */
    String DEFAULT_OEM_ENCODING = "Cp850";

    /**
     * Constant representing an infinite timeout.
     */
    int FOREVER = -1;

    /**
     * When specified as the <code>shareAccess</code> constructor parameter,
     * other SMB clients (including other threads making calls into jCIFS)
     * will not be permitted to access the target file and will receive "The
     * file is being accessed by another process" message.
     */
    int FILE_NO_SHARE = 0x00;
    /**
     * When specified as the <code>shareAccess</code> constructor parameter,
     * other SMB clients will be permitted to read from the target file while
     * this file is open. This constant may be logically OR'd with other share
     * access flags.
     */
    int FILE_SHARE_READ = 0x01;
    /**
     * When specified as the <code>shareAccess</code> constructor parameter,
     * other SMB clients will be permitted to write to the target file while
     * this file is open. This constant may be logically OR'd with other share
     * access flags.
     */
    int FILE_SHARE_WRITE = 0x02;
    /**
     * When specified as the <code>shareAccess</code> constructor parameter,
     * other SMB clients will be permitted to delete the target file while
     * this file is open. This constant may be logically OR'd with other share
     * access flags.
     */
    int FILE_SHARE_DELETE = 0x04;
    /**
     * Default sharing mode for files
     */
    int DEFAULT_SHARING = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    /**
     * Returned by {@link jcifs.SmbResource#getType()} if the resource this <code>SmbFile</code>
     * represents is a regular file or directory.
     */
    int TYPE_FILESYSTEM = 0x01;
    /**
     * Returned by {@link jcifs.SmbResource#getType()} if the resource this <code>SmbFile</code>
     * represents is a workgroup.
     */
    int TYPE_WORKGROUP = 0x02;
    /**
     * Returned by {@link jcifs.SmbResource#getType()} if the resource this <code>SmbFile</code>
     * represents is a server.
     */
    int TYPE_SERVER = 0x04;
    /**
     * Returned by {@link jcifs.SmbResource#getType()} if the resource this <code>SmbFile</code>
     * represents is a share.
     */
    int TYPE_SHARE = 0x08;
    /**
     * Returned by {@link jcifs.SmbResource#getType()} if the resource this <code>SmbFile</code>
     * represents is a named pipe.
     */
    int TYPE_NAMED_PIPE = 0x10;
    /**
     * Returned by {@link jcifs.SmbResource#getType()} if the resource this <code>SmbFile</code>
     * represents is a printer.
     */
    int TYPE_PRINTER = 0x20;
    /**
     * Returned by {@link jcifs.SmbResource#getType()} if the resource this <code>SmbFile</code>
     * represents is a communications device.
     */
    int TYPE_COMM = 0x40;

    /* open flags */

    /**
     * Open for reading only.
     */
    int O_RDONLY = 0x01;
    /**
     * Open for writing only.
     */
    int O_WRONLY = 0x02;
    /**
     * Open for reading and writing.
     */
    int O_RDWR = 0x03;
    /**
     * Open in append mode.
     */
    int O_APPEND = 0x04;

    // Open Function Encoding
    /**
     * Create file if it does not exist.
     */
    int O_CREAT = 0x0010;
    /**
     * Fail if the file exists.
     */
    int O_EXCL = 0x0020;
    /**
     * Truncate file if it exists.
     */
    int O_TRUNC = 0x0040;

}
