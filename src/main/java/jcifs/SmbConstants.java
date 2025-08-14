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
 * @internal
 */
@SuppressWarnings("javadoc")
public interface SmbConstants {

    int DEFAULT_PORT = 445;

    int DEFAULT_MAX_MPX_COUNT = 10;
    int DEFAULT_RESPONSE_TIMEOUT = 30000;
    int DEFAULT_SO_TIMEOUT = 35000;
    int DEFAULT_RCV_BUF_SIZE = 0xFFFF;
    int DEFAULT_SND_BUF_SIZE = 0xFFFF;
    int DEFAULT_NOTIFY_BUF_SIZE = 1024;

    int DEFAULT_SSN_LIMIT = 250;
    int DEFAULT_CONN_TIMEOUT = 35000;

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
    int FLAGS2_SECURITY_REQUIRE_SIGNATURES = 0x0010;
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
    int CAP_LARGE_READX = 0x4000;
    int CAP_LARGE_WRITEX = 0x8000;
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

    int SECURITY_SHARE = 0x00;
    int SECURITY_USER = 0x01;

    int CMD_OFFSET = 4;
    int ERROR_CODE_OFFSET = 5;
    int FLAGS_OFFSET = 9;
    int SIGNATURE_OFFSET = 14;
    int TID_OFFSET = 24;
    int SMB1_HEADER_LENGTH = 32;

    long MILLISECONDS_BETWEEN_1970_AND_1601 = 11644473600000L;

    String DEFAULT_OEM_ENCODING = "Cp850";

    int FOREVER = -1;

    /**
     * When specified as the <tt>shareAccess</tt> constructor parameter,
     * other SMB clients (including other threads making calls into jCIFS)
     * will not be permitted to access the target file and will receive "The
     * file is being accessed by another process" message.
     */
    int FILE_NO_SHARE = 0x00;
    /**
     * When specified as the <tt>shareAccess</tt> constructor parameter,
     * other SMB clients will be permitted to read from the target file while
     * this file is open. This constant may be logically OR'd with other share
     * access flags.
     */
    int FILE_SHARE_READ = 0x01;
    /**
     * When specified as the <tt>shareAccess</tt> constructor parameter,
     * other SMB clients will be permitted to write to the target file while
     * this file is open. This constant may be logically OR'd with other share
     * access flags.
     */
    int FILE_SHARE_WRITE = 0x02;
    /**
     * When specified as the <tt>shareAccess</tt> constructor parameter,
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
     * Returned by {@link jcifs.SmbResource#getType()} if the resource this <tt>SmbFile</tt>
     * represents is a regular file or directory.
     */
    int TYPE_FILESYSTEM = 0x01;
    /**
     * Returned by {@link jcifs.SmbResource#getType()} if the resource this <tt>SmbFile</tt>
     * represents is a workgroup.
     */
    int TYPE_WORKGROUP = 0x02;
    /**
     * Returned by {@link jcifs.SmbResource#getType()} if the resource this <tt>SmbFile</tt>
     * represents is a server.
     */
    int TYPE_SERVER = 0x04;
    /**
     * Returned by {@link jcifs.SmbResource#getType()} if the resource this <tt>SmbFile</tt>
     * represents is a share.
     */
    int TYPE_SHARE = 0x08;
    /**
     * Returned by {@link jcifs.SmbResource#getType()} if the resource this <tt>SmbFile</tt>
     * represents is a named pipe.
     */
    int TYPE_NAMED_PIPE = 0x10;
    /**
     * Returned by {@link jcifs.SmbResource#getType()} if the resource this <tt>SmbFile</tt>
     * represents is a printer.
     */
    int TYPE_PRINTER = 0x20;
    /**
     * Returned by {@link jcifs.SmbResource#getType()} if the resource this <tt>SmbFile</tt>
     * represents is a communications device.
     */
    int TYPE_COMM = 0x40;

    /* open flags */

    int O_RDONLY = 0x01;
    int O_WRONLY = 0x02;
    int O_RDWR = 0x03;
    int O_APPEND = 0x04;

    // Open Function Encoding
    // create if the file does not exist
    int O_CREAT = 0x0010;
    // fail if the file exists
    int O_EXCL = 0x0020;
    // truncate if the file exists
    int O_TRUNC = 0x0040;

}
