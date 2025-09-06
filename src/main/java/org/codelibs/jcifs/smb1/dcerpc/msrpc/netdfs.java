package org.codelibs.jcifs.smb1.dcerpc.msrpc;

import org.codelibs.jcifs.smb1.dcerpc.DcerpcMessage;
import org.codelibs.jcifs.smb1.dcerpc.ndr.NdrBuffer;
import org.codelibs.jcifs.smb1.dcerpc.ndr.NdrException;
import org.codelibs.jcifs.smb1.dcerpc.ndr.NdrLong;
import org.codelibs.jcifs.smb1.dcerpc.ndr.NdrObject;

/**
 * DCE/RPC interface for Distributed File System (DFS) operations.
 * Provides structures and methods for DFS management and enumeration.
 */
public class netdfs {

    /**
     * Default constructor for netdfs
     */
    public netdfs() {
        // Default constructor
    }

    /**
     * Gets the DCE/RPC syntax identifier for the DFS interface
     * @return the syntax identifier string
     */
    public static String getSyntax() {
        return "4fc742e0-4a10-11cf-8273-00aa004ae673:3.0";
    }

    /**
     * DFS volume flavor indicating standalone DFS
     */
    public static final int DFS_VOLUME_FLAVOR_STANDALONE = 0x100;
    /**
     * DFS volume flavor indicating Active Directory blob storage
     */
    public static final int DFS_VOLUME_FLAVOR_AD_BLOB = 0x200;
    /**
     * DFS storage state indicating offline status
     */
    public static final int DFS_STORAGE_STATE_OFFLINE = 0x0001;
    /**
     * DFS storage state indicating online status
     */
    public static final int DFS_STORAGE_STATE_ONLINE = 0x0002;
    /**
     * DFS storage state indicating active status
     */
    public static final int DFS_STORAGE_STATE_ACTIVE = 0x0004;

    /**
     * DFS information level 1 structure containing basic DFS entry information
     */
    public static class DfsInfo1 extends NdrObject {

        /**
         * Default constructor for DfsInfo1
         */
        public DfsInfo1() {
            // Default constructor
        }

        /**
         * The DFS entry path
         */
        public String entry_path;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_referent(entry_path, 1);

            if (entry_path != null) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(entry_path);

            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            final int _entry_pathp = _src.dec_ndr_long();

            if (_entry_pathp != 0) {
                _src = _src.deferred;
                entry_path = _src.dec_ndr_string();

            }
        }
    }

    /**
     * Array structure for DFS enumeration containing level 1 information
     */
    public static class DfsEnumArray1 extends NdrObject {

        /**
         * Default constructor for DfsEnumArray1
         */
        public DfsEnumArray1() {
            // Default constructor
        }

        /**
         * Number of DFS entries in the array
         */
        public int count;
        /**
         * Array of DFS information level 1 structures
         */
        public DfsInfo1[] s;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(count);
            _dst.enc_ndr_referent(s, 1);

            if (s != null) {
                _dst = _dst.deferred;
                final int _ss = count;
                _dst.enc_ndr_long(_ss);
                final int _si = _dst.index;
                _dst.advance(4 * _ss);

                _dst = _dst.derive(_si);
                for (int _i = 0; _i < _ss; _i++) {
                    s[_i].encode(_dst);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            count = _src.dec_ndr_long();
            final int _sp = _src.dec_ndr_long();

            if (_sp != 0) {
                _src = _src.deferred;
                final int _ss = _src.dec_ndr_long();
                final int _si = _src.index;
                _src.advance(4 * _ss);

                if (s == null) {
                    if (_ss < 0 || _ss > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    s = new DfsInfo1[_ss];
                }
                _src = _src.derive(_si);
                for (int _i = 0; _i < _ss; _i++) {
                    if (s[_i] == null) {
                        s[_i] = new DfsInfo1();
                    }
                    s[_i].decode(_src);
                }
            }
        }
    }

    /**
     * DFS storage information structure containing server and share details
     */
    public static class DfsStorageInfo extends NdrObject {

        /**
         * Default constructor for DfsStorageInfo
         */
        public DfsStorageInfo() {
            // Default constructor
        }

        /**
         * Storage state flags
         */
        public int state;
        /**
         * Server name hosting the storage
         */
        public String server_name;
        /**
         * Share name on the server
         */
        public String share_name;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(state);
            _dst.enc_ndr_referent(server_name, 1);
            _dst.enc_ndr_referent(share_name, 1);

            if (server_name != null) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(server_name);

            }
            if (share_name != null) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(share_name);

            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            state = _src.dec_ndr_long();
            final int _server_namep = _src.dec_ndr_long();
            final int _share_namep = _src.dec_ndr_long();

            if (_server_namep != 0) {
                _src = _src.deferred;
                server_name = _src.dec_ndr_string();

            }
            if (_share_namep != 0) {
                _src = _src.deferred;
                share_name = _src.dec_ndr_string();

            }
        }
    }

    /**
     * DFS information level 3 structure containing detailed DFS entry information
     */
    public static class DfsInfo3 extends NdrObject {

        /**
         * Default constructor for DfsInfo3
         */
        public DfsInfo3() {
            // Default constructor
        }

        /**
         * DFS path
         */
        public String path;
        /**
         * Comment or description
         */
        public String comment;
        /**
         * DFS state flags
         */
        public int state;
        /**
         * Number of storage servers
         */
        public int num_stores;
        /**
         * Array of storage information
         */
        public DfsStorageInfo[] stores;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_referent(path, 1);
            _dst.enc_ndr_referent(comment, 1);
            _dst.enc_ndr_long(state);
            _dst.enc_ndr_long(num_stores);
            _dst.enc_ndr_referent(stores, 1);

            if (path != null) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(path);

            }
            if (comment != null) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(comment);

            }
            if (stores != null) {
                _dst = _dst.deferred;
                final int _storess = num_stores;
                _dst.enc_ndr_long(_storess);
                final int _storesi = _dst.index;
                _dst.advance(12 * _storess);

                _dst = _dst.derive(_storesi);
                for (int _i = 0; _i < _storess; _i++) {
                    stores[_i].encode(_dst);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            final int _pathp = _src.dec_ndr_long();
            final int _commentp = _src.dec_ndr_long();
            state = _src.dec_ndr_long();
            num_stores = _src.dec_ndr_long();
            final int _storesp = _src.dec_ndr_long();

            if (_pathp != 0) {
                _src = _src.deferred;
                path = _src.dec_ndr_string();

            }
            if (_commentp != 0) {
                _src = _src.deferred;
                comment = _src.dec_ndr_string();

            }
            if (_storesp != 0) {
                _src = _src.deferred;
                final int _storess = _src.dec_ndr_long();
                final int _storesi = _src.index;
                _src.advance(12 * _storess);

                if (stores == null) {
                    if (_storess < 0 || _storess > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    stores = new DfsStorageInfo[_storess];
                }
                _src = _src.derive(_storesi);
                for (int _i = 0; _i < _storess; _i++) {
                    if (stores[_i] == null) {
                        stores[_i] = new DfsStorageInfo();
                    }
                    stores[_i].decode(_src);
                }
            }
        }
    }

    /**
     * Array structure for DFS enumeration containing level 3 information
     */
    public static class DfsEnumArray3 extends NdrObject {

        /**
         * Default constructor for DfsEnumArray3
         */
        public DfsEnumArray3() {
            // Default constructor
        }

        /**
         * Number of DFS entries in the array
         */
        public int count;
        /**
         * Array of DFS information level 3 structures
         */
        public DfsInfo3[] s;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(count);
            _dst.enc_ndr_referent(s, 1);

            if (s != null) {
                _dst = _dst.deferred;
                final int _ss = count;
                _dst.enc_ndr_long(_ss);
                final int _si = _dst.index;
                _dst.advance(20 * _ss);

                _dst = _dst.derive(_si);
                for (int _i = 0; _i < _ss; _i++) {
                    s[_i].encode(_dst);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            count = _src.dec_ndr_long();
            final int _sp = _src.dec_ndr_long();

            if (_sp != 0) {
                _src = _src.deferred;
                final int _ss = _src.dec_ndr_long();
                final int _si = _src.index;
                _src.advance(20 * _ss);

                if (s == null) {
                    if (_ss < 0 || _ss > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    s = new DfsInfo3[_ss];
                }
                _src = _src.derive(_si);
                for (int _i = 0; _i < _ss; _i++) {
                    if (s[_i] == null) {
                        s[_i] = new DfsInfo3();
                    }
                    s[_i].decode(_src);
                }
            }
        }
    }

    /**
     * DFS information level 200 structure for extended DFS information
     */
    public static class DfsInfo200 extends NdrObject {

        /**
         * Default constructor for DfsInfo200
         */
        public DfsInfo200() {
            // Default constructor
        }

        /**
         * The DFS name
         */
        public String dfs_name;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_referent(dfs_name, 1);

            if (dfs_name != null) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(dfs_name);

            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            final int _dfs_namep = _src.dec_ndr_long();

            if (_dfs_namep != 0) {
                _src = _src.deferred;
                dfs_name = _src.dec_ndr_string();

            }
        }
    }

    /**
     * Array structure for DFS enumeration containing level 200 information
     */
    public static class DfsEnumArray200 extends NdrObject {

        /**
         * Default constructor for DfsEnumArray200
         */
        public DfsEnumArray200() {
            // Default constructor
        }

        /**
         * Number of DFS entries in the array
         */
        public int count;
        /**
         * Array of DFS information level 200 structures
         */
        public DfsInfo200[] s;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(count);
            _dst.enc_ndr_referent(s, 1);

            if (s != null) {
                _dst = _dst.deferred;
                final int _ss = count;
                _dst.enc_ndr_long(_ss);
                final int _si = _dst.index;
                _dst.advance(4 * _ss);

                _dst = _dst.derive(_si);
                for (int _i = 0; _i < _ss; _i++) {
                    s[_i].encode(_dst);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            count = _src.dec_ndr_long();
            final int _sp = _src.dec_ndr_long();

            if (_sp != 0) {
                _src = _src.deferred;
                final int _ss = _src.dec_ndr_long();
                final int _si = _src.index;
                _src.advance(4 * _ss);

                if (s == null) {
                    if (_ss < 0 || _ss > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    s = new DfsInfo200[_ss];
                }
                _src = _src.derive(_si);
                for (int _i = 0; _i < _ss; _i++) {
                    if (s[_i] == null) {
                        s[_i] = new DfsInfo200();
                    }
                    s[_i].decode(_src);
                }
            }
        }
    }

    /**
     * DFS information level 300 structure for extended DFS information
     */
    public static class DfsInfo300 extends NdrObject {

        /**
         * Default constructor for DfsInfo300
         */
        public DfsInfo300() {
            // Default constructor
        }

        /**
         * DFS flags
         */
        public int flags;
        /**
         * The DFS name
         */
        public String dfs_name;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(flags);
            _dst.enc_ndr_referent(dfs_name, 1);

            if (dfs_name != null) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(dfs_name);

            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            flags = _src.dec_ndr_long();
            final int _dfs_namep = _src.dec_ndr_long();

            if (_dfs_namep != 0) {
                _src = _src.deferred;
                dfs_name = _src.dec_ndr_string();

            }
        }
    }

    /**
     * Array structure for DFS enumeration containing level 300 information
     */
    public static class DfsEnumArray300 extends NdrObject {

        /**
         * Default constructor for DfsEnumArray300
         */
        public DfsEnumArray300() {
            // Default constructor
        }

        /**
         * Number of DFS entries in the array
         */
        public int count;
        /**
         * Array of DFS information level 300 structures
         */
        public DfsInfo300[] s;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(count);
            _dst.enc_ndr_referent(s, 1);

            if (s != null) {
                _dst = _dst.deferred;
                final int _ss = count;
                _dst.enc_ndr_long(_ss);
                final int _si = _dst.index;
                _dst.advance(8 * _ss);

                _dst = _dst.derive(_si);
                for (int _i = 0; _i < _ss; _i++) {
                    s[_i].encode(_dst);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            count = _src.dec_ndr_long();
            final int _sp = _src.dec_ndr_long();

            if (_sp != 0) {
                _src = _src.deferred;
                final int _ss = _src.dec_ndr_long();
                final int _si = _src.index;
                _src.advance(8 * _ss);

                if (s == null) {
                    if (_ss < 0 || _ss > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    s = new DfsInfo300[_ss];
                }
                _src = _src.derive(_si);
                for (int _i = 0; _i < _ss; _i++) {
                    if (s[_i] == null) {
                        s[_i] = new DfsInfo300();
                    }
                    s[_i].decode(_src);
                }
            }
        }
    }

    /**
     * DFS enumeration structure containing the level and corresponding data
     */
    public static class DfsEnumStruct extends NdrObject {

        /**
         * Default constructor for DfsEnumStruct
         */
        public DfsEnumStruct() {
            // Default constructor
        }

        /**
         * Information level for the enumeration
         */
        public int level;
        /**
         * Enumeration data object corresponding to the level
         */
        public NdrObject e;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(level);
            final int _descr = level;
            _dst.enc_ndr_long(_descr);
            _dst.enc_ndr_referent(e, 1);

            if (e != null) {
                _dst = _dst.deferred;
                e.encode(_dst);

            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            level = _src.dec_ndr_long();
            _src.dec_ndr_long(); /* union discriminant */
            final int _ep = _src.dec_ndr_long();

            if (_ep != 0) {
                if (e == null) { /* YOYOYO */
                    e = new DfsEnumArray1();
                }
                _src = _src.deferred;
                e.decode(_src);

            }
        }
    }

    /**
     * DCE/RPC message for NetrDfsEnumEx operation to enumerate DFS entries
     */
    public static class NetrDfsEnumEx extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x15;
        }

        /**
         * Return value from the RPC call
         */
        public int retval;
        /**
         * DFS name to enumerate
         */
        public String dfs_name;
        /**
         * Information level for enumeration
         */
        public int level;
        /**
         * Preferred maximum length of returned data
         */
        public int prefmaxlen;
        /**
         * DFS enumeration structure containing results
         */
        public DfsEnumStruct info;
        /**
         * Total number of entries available
         */
        public NdrLong totalentries;

        /**
         * Constructs a NetrDfsEnumEx request
         * @param dfs_name the DFS name to enumerate
         * @param level the information level
         * @param prefmaxlen the preferred maximum length
         * @param info the enumeration structure
         * @param totalentries holder for total entries count
         */
        public NetrDfsEnumEx(final String dfs_name, final int level, final int prefmaxlen, final DfsEnumStruct info,
                final NdrLong totalentries) {
            this.dfs_name = dfs_name;
            this.level = level;
            this.prefmaxlen = prefmaxlen;
            this.info = info;
            this.totalentries = totalentries;
        }

        @Override
        public void encode_in(final NdrBuffer _dst) throws NdrException {
            _dst.enc_ndr_string(dfs_name);
            _dst.enc_ndr_long(level);
            _dst.enc_ndr_long(prefmaxlen);
            _dst.enc_ndr_referent(info, 1);
            if (info != null) {
                info.encode(_dst);

            }
            _dst.enc_ndr_referent(totalentries, 1);
            if (totalentries != null) {
                totalentries.encode(_dst);

            }
        }

        @Override
        public void decode_out(final NdrBuffer _src) throws NdrException {
            final int _infop = _src.dec_ndr_long();
            if (_infop != 0) {
                if (info == null) { /* YOYOYO */
                    info = new DfsEnumStruct();
                }
                info.decode(_src);

            }
            final int _totalentriesp = _src.dec_ndr_long();
            if (_totalentriesp != 0) {
                totalentries.decode(_src);

            }
            retval = _src.dec_ndr_long();
        }
    }
}
