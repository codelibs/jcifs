package jcifs.smb1.dcerpc.msrpc;

import jcifs.smb1.dcerpc.DcerpcMessage;
import jcifs.smb1.dcerpc.rpc;
import jcifs.smb1.dcerpc.ndr.NdrBuffer;
import jcifs.smb1.dcerpc.ndr.NdrException;
import jcifs.smb1.dcerpc.ndr.NdrObject;

/**
 * Security Account Manager Remote (SAMR) protocol implementation for SMB1.
 * This class provides DCE/RPC interface for SAM database operations including
 * user account management, group operations, and domain security functions.
 */
public class samr {

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private samr() {
        // Utility class
    }

    /**
     * Returns the RPC interface syntax UUID and version for SAMR protocol.
     *
     * @return The SAMR interface UUID string
     */
    public static String getSyntax() {
        return "12345778-1234-abcd-ef00-0123456789ac:1.0";
    }

    /** Account control bit flag: Account is disabled */
    public static final int ACB_DISABLED = 1;
    /** Account control bit flag: Home directory is required */
    public static final int ACB_HOMDIRREQ = 2;
    /** Account control bit flag: Password is not required */
    public static final int ACB_PWNOTREQ = 4;
    /** Account control bit flag: Temporary duplicate account */
    public static final int ACB_TEMPDUP = 8;
    /** Account control bit flag: Normal user account */
    public static final int ACB_NORMAL = 16;
    /** Account control bit flag: MNS logon user account */
    public static final int ACB_MNS = 32;
    /** Account control bit flag: Interdomain trust account */
    public static final int ACB_DOMTRUST = 64;
    /** Account control bit flag: Workstation trust account */
    public static final int ACB_WSTRUST = 128;
    /** Account control bit flag: Server trust account */
    public static final int ACB_SVRTRUST = 256;
    /** Account control bit flag: Password does not expire */
    public static final int ACB_PWNOEXP = 512;
    /** Account control bit flag: Account is auto-locked */
    public static final int ACB_AUTOLOCK = 1024;
    /** Account control bit flag: Encrypted text password is allowed */
    public static final int ACB_ENC_TXT_PWD_ALLOWED = 2048;
    /** Account control bit flag: Smart card is required for login */
    public static final int ACB_SMARTCARD_REQUIRED = 4096;
    /** Account control bit flag: Account is trusted for delegation */
    public static final int ACB_TRUSTED_FOR_DELEGATION = 8192;
    /** Account control bit flag: Account is not delegated */
    public static final int ACB_NOT_DELEGATED = 16384;
    /** Account control bit flag: Use DES encryption keys only */
    public static final int ACB_USE_DES_KEY_ONLY = 32768;
    /** Account control bit flag: Pre-authentication is not required */
    public static final int ACB_DONT_REQUIRE_PREAUTH = 65536;

    /**
     * SAMR CloseHandle operation for closing an opened SAM handle.
     * This operation releases resources associated with the handle.
     */
    public static class SamrCloseHandle extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x01;
        }

        /** The return value of the operation */
        public int retval;
        /** The handle to be closed */
        public rpc.policy_handle handle;

        /**
         * Constructs a SamrCloseHandle request.
         *
         * @param handle The policy handle to close
         */
        public SamrCloseHandle(final rpc.policy_handle handle) {
            this.handle = handle;
        }

        @Override
        public void encode_in(final NdrBuffer _dst) throws NdrException {
            handle.encode(_dst);
        }

        @Override
        public void decode_out(final NdrBuffer _src) throws NdrException {
            retval = _src.dec_ndr_long();
        }
    }

    /**
     * SAMR Connect2 operation for establishing a connection to the SAM database.
     * This operation opens the SAM database on a remote server.
     */
    public static class SamrConnect2 extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x39;
        }

        /** The return value of the operation */
        public int retval;
        /** The NetBIOS name of the server to connect to */
        public String system_name;
        /** The desired access rights to the SAM server */
        public int access_mask;
        /** The returned handle to the SAM server */
        public rpc.policy_handle handle;

        /**
         * Constructs a SamrConnect2 request.
         *
         * @param system_name The NetBIOS name of the server
         * @param access_mask The desired access rights
         * @param handle The policy handle to receive the connection handle
         */
        public SamrConnect2(final String system_name, final int access_mask, final rpc.policy_handle handle) {
            this.system_name = system_name;
            this.access_mask = access_mask;
            this.handle = handle;
        }

        @Override
        public void encode_in(final NdrBuffer _dst) throws NdrException {
            _dst.enc_ndr_referent(system_name, 1);
            if (system_name != null) {
                _dst.enc_ndr_string(system_name);

            }
            _dst.enc_ndr_long(access_mask);
        }

        @Override
        public void decode_out(final NdrBuffer _src) throws NdrException {
            handle.decode(_src);
            retval = _src.dec_ndr_long();
        }
    }

    /**
     * SAMR Connect4 operation for establishing a connection to the SAM database.
     * This is an enhanced version of Connect2 with additional parameters.
     */
    public static class SamrConnect4 extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x3e;
        }

        /** The return value of the operation */
        public int retval;
        /** The NetBIOS name of the server to connect to */
        public String system_name;
        /** Reserved parameter, must be set to 2 */
        public int unknown;
        /** The desired access rights to the SAM server */
        public int access_mask;
        /** The returned handle to the SAM server */
        public rpc.policy_handle handle;

        /**
         * Constructs a SamrConnect4 request.
         *
         * @param system_name The NetBIOS name of the server
         * @param unknown Reserved parameter (typically 2)
         * @param access_mask The desired access rights
         * @param handle The policy handle to receive the connection handle
         */
        public SamrConnect4(final String system_name, final int unknown, final int access_mask, final rpc.policy_handle handle) {
            this.system_name = system_name;
            this.unknown = unknown;
            this.access_mask = access_mask;
            this.handle = handle;
        }

        @Override
        public void encode_in(final NdrBuffer _dst) throws NdrException {
            _dst.enc_ndr_referent(system_name, 1);
            if (system_name != null) {
                _dst.enc_ndr_string(system_name);

            }
            _dst.enc_ndr_long(unknown);
            _dst.enc_ndr_long(access_mask);
        }

        @Override
        public void decode_out(final NdrBuffer _src) throws NdrException {
            handle.decode(_src);
            retval = _src.dec_ndr_long();
        }
    }

    /**
     * SAMR OpenDomain operation for opening a domain within the SAM database.
     * This operation obtains a handle to a specific domain.
     */
    public static class SamrOpenDomain extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x07;
        }

        /** The return value of the operation */
        public int retval;
        /** The SAM server handle */
        public rpc.policy_handle handle;
        /** The desired access rights to the domain */
        public int access_mask;
        /** The SID of the domain to open */
        public rpc.sid_t sid;
        /** The returned handle to the domain */
        public rpc.policy_handle domain_handle;

        /**
         * Constructs a SamrOpenDomain request.
         *
         * @param handle The SAM server handle
         * @param access_mask The desired access rights
         * @param sid The SID of the domain
         * @param domain_handle The policy handle to receive the domain handle
         */
        public SamrOpenDomain(final rpc.policy_handle handle, final int access_mask, final rpc.sid_t sid,
                final rpc.policy_handle domain_handle) {
            this.handle = handle;
            this.access_mask = access_mask;
            this.sid = sid;
            this.domain_handle = domain_handle;
        }

        @Override
        public void encode_in(final NdrBuffer _dst) throws NdrException {
            handle.encode(_dst);
            _dst.enc_ndr_long(access_mask);
            sid.encode(_dst);
        }

        @Override
        public void decode_out(final NdrBuffer _src) throws NdrException {
            domain_handle.decode(_src);
            retval = _src.dec_ndr_long();
        }
    }

    /**
     * SAMR SAM Entry structure representing a SAM database entry.
     * Contains the relative ID and name of a SAM object.
     */
    public static class SamrSamEntry extends NdrObject {

        /**
         * Default constructor for SamrSamEntry.
         */
        public SamrSamEntry() {
            // Default constructor
        }

        /** The relative ID (RID) of the SAM entry */
        public int idx;
        /** The name of the SAM entry */
        public rpc.unicode_string name;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(idx);
            _dst.enc_ndr_short(name.length);
            _dst.enc_ndr_short(name.maximum_length);
            _dst.enc_ndr_referent(name.buffer, 1);

            if (name.buffer != null) {
                _dst = _dst.deferred;
                final int _name_bufferl = name.length / 2;
                final int _name_buffers = name.maximum_length / 2;
                _dst.enc_ndr_long(_name_buffers);
                _dst.enc_ndr_long(0);
                _dst.enc_ndr_long(_name_bufferl);
                final int _name_bufferi = _dst.index;
                _dst.advance(2 * _name_bufferl);

                _dst = _dst.derive(_name_bufferi);
                for (int _i = 0; _i < _name_bufferl; _i++) {
                    _dst.enc_ndr_short(name.buffer[_i]);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            idx = _src.dec_ndr_long();
            _src.align(4);
            if (name == null) {
                name = new rpc.unicode_string();
            }
            name.length = (short) _src.dec_ndr_short();
            name.maximum_length = (short) _src.dec_ndr_short();
            final int _name_bufferp = _src.dec_ndr_long();

            if (_name_bufferp != 0) {
                _src = _src.deferred;
                final int _name_buffers = _src.dec_ndr_long();
                _src.dec_ndr_long();
                final int _name_bufferl = _src.dec_ndr_long();
                final int _name_bufferi = _src.index;
                _src.advance(2 * _name_bufferl);

                if (name.buffer == null) {
                    if (_name_buffers < 0 || _name_buffers > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    name.buffer = new short[_name_buffers];
                }
                _src = _src.derive(_name_bufferi);
                for (int _i = 0; _i < _name_bufferl; _i++) {
                    name.buffer[_i] = (short) _src.dec_ndr_short();
                }
            }
        }
    }

    /**
     * SAMR SAM Array structure representing an array of SAM entries.
     * Used to return multiple SAM objects in enumeration operations.
     */
    public static class SamrSamArray extends NdrObject {

        /**
         * Default constructor for SamrSamArray.
         */
        public SamrSamArray() {
            // Default constructor
        }

        /** The number of entries in the array */
        public int count;
        /** The array of SAM entries */
        public SamrSamEntry[] entries;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(count);
            _dst.enc_ndr_referent(entries, 1);

            if (entries != null) {
                _dst = _dst.deferred;
                final int _entriess = count;
                _dst.enc_ndr_long(_entriess);
                final int _entriesi = _dst.index;
                _dst.advance(12 * _entriess);

                _dst = _dst.derive(_entriesi);
                for (int _i = 0; _i < _entriess; _i++) {
                    entries[_i].encode(_dst);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            count = _src.dec_ndr_long();
            final int _entriesp = _src.dec_ndr_long();

            if (_entriesp != 0) {
                _src = _src.deferred;
                final int _entriess = _src.dec_ndr_long();
                final int _entriesi = _src.index;
                _src.advance(12 * _entriess);

                if (entries == null) {
                    if (_entriess < 0 || _entriess > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    entries = new SamrSamEntry[_entriess];
                }
                _src = _src.derive(_entriesi);
                for (int _i = 0; _i < _entriess; _i++) {
                    if (entries[_i] == null) {
                        entries[_i] = new SamrSamEntry();
                    }
                    entries[_i].decode(_src);
                }
            }
        }
    }

    /**
     * SAMR EnumerateAliasesInDomain operation for listing aliases in a domain.
     * This operation retrieves a list of alias accounts from the specified domain.
     */
    public static class SamrEnumerateAliasesInDomain extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x0f;
        }

        /** The return value of the operation */
        public int retval;
        /** The handle to the domain */
        public rpc.policy_handle domain_handle;
        /** The enumeration context handle */
        public int resume_handle;
        /** Account control flags filter */
        public int acct_flags;
        /** The returned array of SAM entries */
        public SamrSamArray sam;
        /** The number of entries returned */
        public int num_entries;

        /**
         * Constructs a SamrEnumerateAliasesInDomain request.
         *
         * @param domain_handle The domain handle
         * @param resume_handle The enumeration context
         * @param acct_flags Account control flags filter
         * @param sam The SAM array to receive results
         * @param num_entries The number of entries to return
         */
        public SamrEnumerateAliasesInDomain(final rpc.policy_handle domain_handle, final int resume_handle, final int acct_flags,
                final SamrSamArray sam, final int num_entries) {
            this.domain_handle = domain_handle;
            this.resume_handle = resume_handle;
            this.acct_flags = acct_flags;
            this.sam = sam;
            this.num_entries = num_entries;
        }

        @Override
        public void encode_in(final NdrBuffer _dst) throws NdrException {
            domain_handle.encode(_dst);
            _dst.enc_ndr_long(resume_handle);
            _dst.enc_ndr_long(acct_flags);
        }

        @Override
        public void decode_out(final NdrBuffer _src) throws NdrException {
            resume_handle = _src.dec_ndr_long();
            final int _samp = _src.dec_ndr_long();
            if (_samp != 0) {
                if (sam == null) { /* YOYOYO */
                    sam = new SamrSamArray();
                }
                sam.decode(_src);

            }
            num_entries = _src.dec_ndr_long();
            retval = _src.dec_ndr_long();
        }
    }

    /**
     * SAMR OpenAlias operation for opening an alias in the SAM database.
     * This operation obtains a handle to a specific alias.
     */
    public static class SamrOpenAlias extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x1b;
        }

        /** The return value of the operation */
        public int retval;
        /** The handle to the domain */
        public rpc.policy_handle domain_handle;
        /** The desired access rights to the alias */
        public int access_mask;
        /** The relative ID of the alias to open */
        public int rid;
        /** The returned handle to the alias */
        public rpc.policy_handle alias_handle;

        /**
         * Constructs a SamrOpenAlias request.
         *
         * @param domain_handle The domain handle
         * @param access_mask The desired access rights
         * @param rid The relative ID of the alias
         * @param alias_handle The policy handle to receive the alias handle
         */
        public SamrOpenAlias(final rpc.policy_handle domain_handle, final int access_mask, final int rid,
                final rpc.policy_handle alias_handle) {
            this.domain_handle = domain_handle;
            this.access_mask = access_mask;
            this.rid = rid;
            this.alias_handle = alias_handle;
        }

        @Override
        public void encode_in(final NdrBuffer _dst) throws NdrException {
            domain_handle.encode(_dst);
            _dst.enc_ndr_long(access_mask);
            _dst.enc_ndr_long(rid);
        }

        @Override
        public void decode_out(final NdrBuffer _src) throws NdrException {
            alias_handle.decode(_src);
            retval = _src.dec_ndr_long();
        }
    }

    /**
     * SAMR GetMembersInAlias operation for retrieving alias members.
     * This operation returns the SIDs of all members in the specified alias.
     */
    public static class SamrGetMembersInAlias extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x21;
        }

        /** The return value of the operation */
        public int retval;
        /** The handle to the alias */
        public rpc.policy_handle alias_handle;
        /** The array of SIDs that are members of the alias */
        public lsarpc.LsarSidArray sids;

        /**
         * Constructs a SamrGetMembersInAlias request.
         *
         * @param alias_handle The alias handle
         * @param sids The array to receive member SIDs
         */
        public SamrGetMembersInAlias(final rpc.policy_handle alias_handle, final lsarpc.LsarSidArray sids) {
            this.alias_handle = alias_handle;
            this.sids = sids;
        }

        @Override
        public void encode_in(final NdrBuffer _dst) throws NdrException {
            alias_handle.encode(_dst);
        }

        @Override
        public void decode_out(final NdrBuffer _src) throws NdrException {
            sids.decode(_src);
            retval = _src.dec_ndr_long();
        }
    }

    /** Security group attribute: Mandatory group that cannot be disabled */
    public static final int SE_GROUP_MANDATORY = 1;
    /** Security group attribute: Group is enabled by default */
    public static final int SE_GROUP_ENABLED_BY_DEFAULT = 2;
    /** Security group attribute: Group is enabled for use */
    public static final int SE_GROUP_ENABLED = 4;
    /** Security group attribute: Group can be assigned as owner of objects */
    public static final int SE_GROUP_OWNER = 8;
    /** Security group attribute: Group is used for deny-only checks */
    public static final int SE_GROUP_USE_FOR_DENY_ONLY = 16;
    /** Security group attribute: Domain-local group */
    public static final int SE_GROUP_RESOURCE = 536870912;
    /** Security group attribute: Group represents a logon identifier */
    public static final int SE_GROUP_LOGON_ID = -1073741824;

    /**
     * SAMR RID with attribute structure.
     * Represents a relative identifier (RID) with associated attribute flags.
     */
    public static class SamrRidWithAttribute extends NdrObject {

        /**
         * Default constructor for SamrRidWithAttribute.
         */
        public SamrRidWithAttribute() {
            // Default constructor
        }

        /** The relative identifier (RID) */
        public int rid;
        /** The attributes associated with the RID */
        public int attributes;

        @Override
        public void encode(final NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(rid);
            _dst.enc_ndr_long(attributes);

        }

        @Override
        public void decode(final NdrBuffer _src) throws NdrException {
            _src.align(4);
            rid = _src.dec_ndr_long();
            attributes = _src.dec_ndr_long();

        }
    }

    /**
     * SAMR RID with attribute array structure.
     * Contains an array of RIDs with their associated attributes.
     */
    public static class SamrRidWithAttributeArray extends NdrObject {

        /**
         * Default constructor for SamrRidWithAttributeArray.
         */
        public SamrRidWithAttributeArray() {
            // Default constructor
        }

        /** The number of RIDs in the array */
        public int count;
        /** The array of RIDs with attributes */
        public SamrRidWithAttribute[] rids;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(count);
            _dst.enc_ndr_referent(rids, 1);

            if (rids != null) {
                _dst = _dst.deferred;
                final int _ridss = count;
                _dst.enc_ndr_long(_ridss);
                final int _ridsi = _dst.index;
                _dst.advance(8 * _ridss);

                _dst = _dst.derive(_ridsi);
                for (int _i = 0; _i < _ridss; _i++) {
                    rids[_i].encode(_dst);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            count = _src.dec_ndr_long();
            final int _ridsp = _src.dec_ndr_long();

            if (_ridsp != 0) {
                _src = _src.deferred;
                final int _ridss = _src.dec_ndr_long();
                final int _ridsi = _src.index;
                _src.advance(8 * _ridss);

                if (rids == null) {
                    if (_ridss < 0 || _ridss > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    rids = new SamrRidWithAttribute[_ridss];
                }
                _src = _src.derive(_ridsi);
                for (int _i = 0; _i < _ridss; _i++) {
                    if (rids[_i] == null) {
                        rids[_i] = new SamrRidWithAttribute();
                    }
                    rids[_i].decode(_src);
                }
            }
        }
    }
}
