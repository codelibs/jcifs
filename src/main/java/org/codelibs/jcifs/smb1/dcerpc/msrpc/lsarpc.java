package org.codelibs.jcifs.smb1.dcerpc.msrpc;

import org.codelibs.jcifs.smb1.dcerpc.DcerpcMessage;
import org.codelibs.jcifs.smb1.dcerpc.rpc;
import org.codelibs.jcifs.smb1.dcerpc.ndr.NdrBuffer;
import org.codelibs.jcifs.smb1.dcerpc.ndr.NdrException;
import org.codelibs.jcifs.smb1.dcerpc.ndr.NdrObject;
import org.codelibs.jcifs.smb1.dcerpc.ndr.NdrSmall;

/**
 * LSA RPC (Local Security Authority Remote Procedure Call) definitions.
 * Provides interface definitions and data structures for LSA RPC operations.
 */
public class lsarpc {

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private lsarpc() {
        // Utility class
    }

    /**
     * Returns the RPC syntax identifier for LSA RPC interface.
     *
     * @return the RPC syntax string
     */
    public static String getSyntax() {
        return "12345778-1234-abcd-ef00-0123456789ab:0.0";
    }

    /**
     * LSA Quality of Service information.
     */
    public static class LsarQosInfo extends NdrObject {

        /**
         * Default constructor for LsarQosInfo.
         */
        public LsarQosInfo() {
            // Default constructor
        }

        /** Length of the QoS information. */
        public int length;
        /** Security impersonation level. */
        public short impersonation_level;
        /** Context tracking mode. */
        public byte context_mode;
        /** Indicates if only effective privileges should be used. */
        public byte effective_only;

        @Override
        public void encode(final NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(length);
            _dst.enc_ndr_short(impersonation_level);
            _dst.enc_ndr_small(context_mode);
            _dst.enc_ndr_small(effective_only);

        }

        @Override
        public void decode(final NdrBuffer _src) throws NdrException {
            _src.align(4);
            length = _src.dec_ndr_long();
            impersonation_level = (short) _src.dec_ndr_short();
            context_mode = (byte) _src.dec_ndr_small();
            effective_only = (byte) _src.dec_ndr_small();

        }
    }

    /**
     * LSA object attributes for policy and resource access.
     */
    public static class LsarObjectAttributes extends NdrObject {

        /**
         * Default constructor for LsarObjectAttributes.
         */
        public LsarObjectAttributes() {
            // Default constructor
        }

        /** Length of the object attributes structure. */
        public int length;
        /** Handle to the root directory. */
        public NdrSmall root_directory;
        /** Name of the object. */
        public rpc.unicode_string object_name;
        /** Object attributes flags. */
        public int attributes;
        /** Security descriptor for the object. */
        public int security_descriptor;
        /** Quality of Service information. */
        public LsarQosInfo security_quality_of_service;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(length);
            _dst.enc_ndr_referent(root_directory, 1);
            _dst.enc_ndr_referent(object_name, 1);
            _dst.enc_ndr_long(attributes);
            _dst.enc_ndr_long(security_descriptor);
            _dst.enc_ndr_referent(security_quality_of_service, 1);

            if (root_directory != null) {
                _dst = _dst.deferred;
                root_directory.encode(_dst);

            }
            if (object_name != null) {
                _dst = _dst.deferred;
                object_name.encode(_dst);

            }
            if (security_quality_of_service != null) {
                _dst = _dst.deferred;
                security_quality_of_service.encode(_dst);

            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            length = _src.dec_ndr_long();
            final int _root_directoryp = _src.dec_ndr_long();
            final int _object_namep = _src.dec_ndr_long();
            attributes = _src.dec_ndr_long();
            security_descriptor = _src.dec_ndr_long();
            final int _security_quality_of_servicep = _src.dec_ndr_long();

            if (_root_directoryp != 0) {
                _src = _src.deferred;
                root_directory.decode(_src);

            }
            if (_object_namep != 0) {
                if (object_name == null) { /* YOYOYO */
                    object_name = new rpc.unicode_string();
                }
                _src = _src.deferred;
                object_name.decode(_src);

            }
            if (_security_quality_of_servicep != 0) {
                if (security_quality_of_service == null) { /* YOYOYO */
                    security_quality_of_service = new LsarQosInfo();
                }
                _src = _src.deferred;
                security_quality_of_service.decode(_src);

            }
        }
    }

    /**
     * LSA domain information structure.
     */
    public static class LsarDomainInfo extends NdrObject {

        /**
         * Default constructor for LsarDomainInfo.
         */
        public LsarDomainInfo() {
            // Default constructor
        }

        /** Domain name. */
        public rpc.unicode_string name;
        /** Domain security identifier. */
        public rpc.sid_t sid;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_short(name.length);
            _dst.enc_ndr_short(name.maximum_length);
            _dst.enc_ndr_referent(name.buffer, 1);
            _dst.enc_ndr_referent(sid, 1);

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
            if (sid != null) {
                _dst = _dst.deferred;
                sid.encode(_dst);

            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            _src.align(4);
            if (name == null) {
                name = new rpc.unicode_string();
            }
            name.length = (short) _src.dec_ndr_short();
            name.maximum_length = (short) _src.dec_ndr_short();
            final int _name_bufferp = _src.dec_ndr_long();
            final int _sidp = _src.dec_ndr_long();

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
            if (_sidp != 0) {
                if (sid == null) { /* YOYOYO */
                    sid = new rpc.sid_t();
                }
                _src = _src.deferred;
                sid.decode(_src);

            }
        }
    }

    /**
     * LSA DNS domain information structure.
     */
    public static class LsarDnsDomainInfo extends NdrObject {

        /**
         * Default constructor for LsarDnsDomainInfo.
         */
        public LsarDnsDomainInfo() {
            // Default constructor
        }

        /** Domain NetBIOS name. */
        public rpc.unicode_string name;
        /** DNS domain name. */
        public rpc.unicode_string dns_domain;
        /** DNS forest name. */
        public rpc.unicode_string dns_forest;
        /** Domain GUID. */
        public rpc.uuid_t domain_guid;
        /** Domain security identifier. */
        public rpc.sid_t sid;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_short(name.length);
            _dst.enc_ndr_short(name.maximum_length);
            _dst.enc_ndr_referent(name.buffer, 1);
            _dst.enc_ndr_short(dns_domain.length);
            _dst.enc_ndr_short(dns_domain.maximum_length);
            _dst.enc_ndr_referent(dns_domain.buffer, 1);
            _dst.enc_ndr_short(dns_forest.length);
            _dst.enc_ndr_short(dns_forest.maximum_length);
            _dst.enc_ndr_referent(dns_forest.buffer, 1);
            _dst.enc_ndr_long(domain_guid.time_low);
            _dst.enc_ndr_short(domain_guid.time_mid);
            _dst.enc_ndr_short(domain_guid.time_hi_and_version);
            _dst.enc_ndr_small(domain_guid.clock_seq_hi_and_reserved);
            _dst.enc_ndr_small(domain_guid.clock_seq_low);
            final int _domain_guid_nodes = 6;
            final int _domain_guid_nodei = _dst.index;
            _dst.advance(1 * _domain_guid_nodes);
            _dst.enc_ndr_referent(sid, 1);

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
            if (dns_domain.buffer != null) {
                _dst = _dst.deferred;
                final int _dns_domain_bufferl = dns_domain.length / 2;
                final int _dns_domain_buffers = dns_domain.maximum_length / 2;
                _dst.enc_ndr_long(_dns_domain_buffers);
                _dst.enc_ndr_long(0);
                _dst.enc_ndr_long(_dns_domain_bufferl);
                final int _dns_domain_bufferi = _dst.index;
                _dst.advance(2 * _dns_domain_bufferl);

                _dst = _dst.derive(_dns_domain_bufferi);
                for (int _i = 0; _i < _dns_domain_bufferl; _i++) {
                    _dst.enc_ndr_short(dns_domain.buffer[_i]);
                }
            }
            if (dns_forest.buffer != null) {
                _dst = _dst.deferred;
                final int _dns_forest_bufferl = dns_forest.length / 2;
                final int _dns_forest_buffers = dns_forest.maximum_length / 2;
                _dst.enc_ndr_long(_dns_forest_buffers);
                _dst.enc_ndr_long(0);
                _dst.enc_ndr_long(_dns_forest_bufferl);
                final int _dns_forest_bufferi = _dst.index;
                _dst.advance(2 * _dns_forest_bufferl);

                _dst = _dst.derive(_dns_forest_bufferi);
                for (int _i = 0; _i < _dns_forest_bufferl; _i++) {
                    _dst.enc_ndr_short(dns_forest.buffer[_i]);
                }
            }
            _dst = _dst.derive(_domain_guid_nodei);
            for (int _i = 0; _i < _domain_guid_nodes; _i++) {
                _dst.enc_ndr_small(domain_guid.node[_i]);
            }
            if (sid != null) {
                _dst = _dst.deferred;
                sid.encode(_dst);

            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            _src.align(4);
            if (name == null) {
                name = new rpc.unicode_string();
            }
            name.length = (short) _src.dec_ndr_short();
            name.maximum_length = (short) _src.dec_ndr_short();
            final int _name_bufferp = _src.dec_ndr_long();
            _src.align(4);
            if (dns_domain == null) {
                dns_domain = new rpc.unicode_string();
            }
            dns_domain.length = (short) _src.dec_ndr_short();
            dns_domain.maximum_length = (short) _src.dec_ndr_short();
            final int _dns_domain_bufferp = _src.dec_ndr_long();
            _src.align(4);
            if (dns_forest == null) {
                dns_forest = new rpc.unicode_string();
            }
            dns_forest.length = (short) _src.dec_ndr_short();
            dns_forest.maximum_length = (short) _src.dec_ndr_short();
            final int _dns_forest_bufferp = _src.dec_ndr_long();
            _src.align(4);
            if (domain_guid == null) {
                domain_guid = new rpc.uuid_t();
            }
            domain_guid.time_low = _src.dec_ndr_long();
            domain_guid.time_mid = (short) _src.dec_ndr_short();
            domain_guid.time_hi_and_version = (short) _src.dec_ndr_short();
            domain_guid.clock_seq_hi_and_reserved = (byte) _src.dec_ndr_small();
            domain_guid.clock_seq_low = (byte) _src.dec_ndr_small();
            final int _domain_guid_nodes = 6;
            final int _domain_guid_nodei = _src.index;
            _src.advance(1 * _domain_guid_nodes);
            final int _sidp = _src.dec_ndr_long();

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
            if (_dns_domain_bufferp != 0) {
                _src = _src.deferred;
                final int _dns_domain_buffers = _src.dec_ndr_long();
                _src.dec_ndr_long();
                final int _dns_domain_bufferl = _src.dec_ndr_long();
                final int _dns_domain_bufferi = _src.index;
                _src.advance(2 * _dns_domain_bufferl);

                if (dns_domain.buffer == null) {
                    if (_dns_domain_buffers < 0 || _dns_domain_buffers > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    dns_domain.buffer = new short[_dns_domain_buffers];
                }
                _src = _src.derive(_dns_domain_bufferi);
                for (int _i = 0; _i < _dns_domain_bufferl; _i++) {
                    dns_domain.buffer[_i] = (short) _src.dec_ndr_short();
                }
            }
            if (_dns_forest_bufferp != 0) {
                _src = _src.deferred;
                final int _dns_forest_buffers = _src.dec_ndr_long();
                _src.dec_ndr_long();
                final int _dns_forest_bufferl = _src.dec_ndr_long();
                final int _dns_forest_bufferi = _src.index;
                _src.advance(2 * _dns_forest_bufferl);

                if (dns_forest.buffer == null) {
                    if (_dns_forest_buffers < 0 || _dns_forest_buffers > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    dns_forest.buffer = new short[_dns_forest_buffers];
                }
                _src = _src.derive(_dns_forest_bufferi);
                for (int _i = 0; _i < _dns_forest_bufferl; _i++) {
                    dns_forest.buffer[_i] = (short) _src.dec_ndr_short();
                }
            }
            if (domain_guid.node == null) {
                if (_domain_guid_nodes < 0 || _domain_guid_nodes > 0xFFFF) {
                    throw new NdrException(NdrException.INVALID_CONFORMANCE);
                }
                domain_guid.node = new byte[_domain_guid_nodes];
            }
            _src = _src.derive(_domain_guid_nodei);
            for (int _i = 0; _i < _domain_guid_nodes; _i++) {
                domain_guid.node[_i] = (byte) _src.dec_ndr_small();
            }
            if (_sidp != 0) {
                if (sid == null) { /* YOYOYO */
                    sid = new rpc.sid_t();
                }
                _src = _src.deferred;
                sid.decode(_src);

            }
        }
    }

    /** Policy information level for audit events. */
    public static final int POLICY_INFO_AUDIT_EVENTS = 2;
    /** Policy information level for primary domain. */
    public static final int POLICY_INFO_PRIMARY_DOMAIN = 3;
    /** Policy information level for account domain. */
    public static final int POLICY_INFO_ACCOUNT_DOMAIN = 5;
    /** Policy information level for server role. */
    public static final int POLICY_INFO_SERVER_ROLE = 6;
    /** Policy information level for modification details. */
    public static final int POLICY_INFO_MODIFICATION = 9;
    /** Policy information level for DNS domain information. */
    public static final int POLICY_INFO_DNS_DOMAIN = 12;

    /**
     * LSA SIDObject pointer structure.
     */
    public static class LsarSidPtr extends NdrObject {

        /**
         * Default constructor for LsarSidPtr.
         */
        public LsarSidPtr() {
            // Default constructor
        }

        /** Security identifier. */
        public rpc.sid_t sid;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_referent(sid, 1);

            if (sid != null) {
                _dst = _dst.deferred;
                sid.encode(_dst);

            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            final int _sidp = _src.dec_ndr_long();

            if (_sidp != 0) {
                if (sid == null) { /* YOYOYO */
                    sid = new rpc.sid_t();
                }
                _src = _src.deferred;
                sid.decode(_src);

            }
        }
    }

    /**
     * LSA SIDObject array structure for batch SIDObject operations.
     */
    public static class LsarSidArray extends NdrObject {

        /**
         * Default constructor for LsarSidArray.
         */
        public LsarSidArray() {
            // Default constructor
        }

        /** Number of SIDs in the array. */
        public int num_sids;
        /** Array of SIDObject pointers. */
        public LsarSidPtr[] sids;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(num_sids);
            _dst.enc_ndr_referent(sids, 1);

            if (sids != null) {
                _dst = _dst.deferred;
                final int _sidss = num_sids;
                _dst.enc_ndr_long(_sidss);
                final int _sidsi = _dst.index;
                _dst.advance(4 * _sidss);

                _dst = _dst.derive(_sidsi);
                for (int _i = 0; _i < _sidss; _i++) {
                    sids[_i].encode(_dst);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            num_sids = _src.dec_ndr_long();
            final int _sidsp = _src.dec_ndr_long();

            if (_sidsp != 0) {
                _src = _src.deferred;
                final int _sidss = _src.dec_ndr_long();
                final int _sidsi = _src.index;
                _src.advance(4 * _sidss);

                if (sids == null) {
                    if (_sidss < 0 || _sidss > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    sids = new LsarSidPtr[_sidss];
                }
                _src = _src.derive(_sidsi);
                for (int _i = 0; _i < _sidss; _i++) {
                    if (sids[_i] == null) {
                        sids[_i] = new LsarSidPtr();
                    }
                    sids[_i].decode(_src);
                }
            }
        }
    }

    /** SIDObject name type: none or unused. */
    public static final int SID_NAME_USE_NONE = 0;
    /** SIDObject name type: user account. */
    public static final int SID_NAME_USER = 1;
    /** SIDObject name type: domain group. */
    public static final int SID_NAME_DOM_GRP = 2;
    /** SIDObject name type: domain. */
    public static final int SID_NAME_DOMAIN = 3;
    /** SIDObject name type: alias. */
    public static final int SID_NAME_ALIAS = 4;
    /** SIDObject name type: well-known group. */
    public static final int SID_NAME_WKN_GRP = 5;
    /** SIDObject name type: deleted account. */
    public static final int SID_NAME_DELETED = 6;
    /** SIDObject name type: invalid. */
    public static final int SID_NAME_INVALID = 7;
    /** SIDObject name type: unknown. */
    public static final int SID_NAME_UNKNOWN = 8;

    /**
     * LSA translated SIDObject structure for name to SIDObject lookups.
     */
    public static class LsarTranslatedSid extends NdrObject {

        /**
         * Default constructor for LsarTranslatedSid.
         */
        public LsarTranslatedSid() {
            // Default constructor
        }

        /** SIDObject type. */
        public int sid_type;
        /** Relative identifier. */
        public int rid;
        /** Index of the SIDObject in the domain list. */
        public int sid_index;

        @Override
        public void encode(final NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_short(sid_type);
            _dst.enc_ndr_long(rid);
            _dst.enc_ndr_long(sid_index);

        }

        @Override
        public void decode(final NdrBuffer _src) throws NdrException {
            _src.align(4);
            sid_type = _src.dec_ndr_short();
            rid = _src.dec_ndr_long();
            sid_index = _src.dec_ndr_long();

        }
    }

    /**
     * LSA translated SIDObject array structure.
     */
    public static class LsarTransSidArray extends NdrObject {

        /**
         * Default constructor for LsarTransSidArray.
         */
        public LsarTransSidArray() {
            // Default constructor
        }

        /** Number of SIDs in the array. */
        public int count;
        /** Array of translated SIDs. */
        public LsarTranslatedSid[] sids;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(count);
            _dst.enc_ndr_referent(sids, 1);

            if (sids != null) {
                _dst = _dst.deferred;
                final int _sidss = count;
                _dst.enc_ndr_long(_sidss);
                final int _sidsi = _dst.index;
                _dst.advance(12 * _sidss);

                _dst = _dst.derive(_sidsi);
                for (int _i = 0; _i < _sidss; _i++) {
                    sids[_i].encode(_dst);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            count = _src.dec_ndr_long();
            final int _sidsp = _src.dec_ndr_long();

            if (_sidsp != 0) {
                _src = _src.deferred;
                final int _sidss = _src.dec_ndr_long();
                final int _sidsi = _src.index;
                _src.advance(12 * _sidss);

                if (sids == null) {
                    if (_sidss < 0 || _sidss > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    sids = new LsarTranslatedSid[_sidss];
                }
                _src = _src.derive(_sidsi);
                for (int _i = 0; _i < _sidss; _i++) {
                    if (sids[_i] == null) {
                        sids[_i] = new LsarTranslatedSid();
                    }
                    sids[_i].decode(_src);
                }
            }
        }
    }

    /**
     * LSA trust information structure.
     */
    public static class LsarTrustInformation extends NdrObject {

        /**
         * Default constructor for LsarTrustInformation.
         */
        public LsarTrustInformation() {
            // Default constructor
        }

        /** Domain name. */
        public rpc.unicode_string name;
        /** Domain security identifier. */
        public rpc.sid_t sid;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_short(name.length);
            _dst.enc_ndr_short(name.maximum_length);
            _dst.enc_ndr_referent(name.buffer, 1);
            _dst.enc_ndr_referent(sid, 1);

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
            if (sid != null) {
                _dst = _dst.deferred;
                sid.encode(_dst);

            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            _src.align(4);
            if (name == null) {
                name = new rpc.unicode_string();
            }
            name.length = (short) _src.dec_ndr_short();
            name.maximum_length = (short) _src.dec_ndr_short();
            final int _name_bufferp = _src.dec_ndr_long();
            final int _sidp = _src.dec_ndr_long();

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
            if (_sidp != 0) {
                if (sid == null) { /* YOYOYO */
                    sid = new rpc.sid_t();
                }
                _src = _src.deferred;
                sid.decode(_src);

            }
        }
    }

    /**
     * LSA referenced domain list structure.
     */
    public static class LsarRefDomainList extends NdrObject {

        /**
         * Default constructor for LsarRefDomainList.
         */
        public LsarRefDomainList() {
            // Default constructor
        }

        /** Number of domains in the list. */
        public int count;
        /** Array of trust information for domains. */
        public LsarTrustInformation[] domains;
        /** Maximum count of domains. */
        public int max_count;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(count);
            _dst.enc_ndr_referent(domains, 1);
            _dst.enc_ndr_long(max_count);

            if (domains != null) {
                _dst = _dst.deferred;
                final int _domainss = count;
                _dst.enc_ndr_long(_domainss);
                final int _domainsi = _dst.index;
                _dst.advance(12 * _domainss);

                _dst = _dst.derive(_domainsi);
                for (int _i = 0; _i < _domainss; _i++) {
                    domains[_i].encode(_dst);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            count = _src.dec_ndr_long();
            final int _domainsp = _src.dec_ndr_long();
            max_count = _src.dec_ndr_long();

            if (_domainsp != 0) {
                _src = _src.deferred;
                final int _domainss = _src.dec_ndr_long();
                final int _domainsi = _src.index;
                _src.advance(12 * _domainss);

                if (domains == null) {
                    if (_domainss < 0 || _domainss > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    domains = new LsarTrustInformation[_domainss];
                }
                _src = _src.derive(_domainsi);
                for (int _i = 0; _i < _domainss; _i++) {
                    if (domains[_i] == null) {
                        domains[_i] = new LsarTrustInformation();
                    }
                    domains[_i].decode(_src);
                }
            }
        }
    }

    /**
     * LSA translated name structure for SIDObject to name lookups.
     */
    public static class LsarTranslatedName extends NdrObject {

        /**
         * Default constructor for LsarTranslatedName.
         */
        public LsarTranslatedName() {
            // Default constructor
        }

        /** SIDObject type for the name. */
        public short sid_type;
        /** Translated name. */
        public rpc.unicode_string name;
        /** Index of the SIDObject in the domain list. */
        public int sid_index;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_short(sid_type);
            _dst.enc_ndr_short(name.length);
            _dst.enc_ndr_short(name.maximum_length);
            _dst.enc_ndr_referent(name.buffer, 1);
            _dst.enc_ndr_long(sid_index);

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
            sid_type = (short) _src.dec_ndr_short();
            _src.align(4);
            if (name == null) {
                name = new rpc.unicode_string();
            }
            name.length = (short) _src.dec_ndr_short();
            name.maximum_length = (short) _src.dec_ndr_short();
            final int _name_bufferp = _src.dec_ndr_long();
            sid_index = _src.dec_ndr_long();

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
     * LSA translated name array structure.
     */
    public static class LsarTransNameArray extends NdrObject {

        /**
         * Default constructor for LsarTransNameArray.
         */
        public LsarTransNameArray() {
            // Default constructor
        }

        /** Number of names in the array. */
        public int count;
        /** Array of translated names. */
        public LsarTranslatedName[] names;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(count);
            _dst.enc_ndr_referent(names, 1);

            if (names != null) {
                _dst = _dst.deferred;
                final int _namess = count;
                _dst.enc_ndr_long(_namess);
                final int _namesi = _dst.index;
                _dst.advance(16 * _namess);

                _dst = _dst.derive(_namesi);
                for (int _i = 0; _i < _namess; _i++) {
                    names[_i].encode(_dst);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            count = _src.dec_ndr_long();
            final int _namesp = _src.dec_ndr_long();

            if (_namesp != 0) {
                _src = _src.deferred;
                final int _namess = _src.dec_ndr_long();
                final int _namesi = _src.index;
                _src.advance(16 * _namess);

                if (names == null) {
                    if (_namess < 0 || _namess > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    names = new LsarTranslatedName[_namess];
                }
                _src = _src.derive(_namesi);
                for (int _i = 0; _i < _namess; _i++) {
                    if (names[_i] == null) {
                        names[_i] = new LsarTranslatedName();
                    }
                    names[_i].decode(_src);
                }
            }
        }
    }

    /**
     * LSA close handle message.
     */
    public static class LsarClose extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x00;
        }

        /** Return value from the RPC call. */
        public int retval;
        /** Policy handle to be closed. */
        public rpc.policy_handle handle;

        /**
         * Creates a new LsarClose message.
         *
         * @param handle the policy handle to close
         */
        public LsarClose(final rpc.policy_handle handle) {
            this.handle = handle;
        }

        @Override
        public void encode_in(final NdrBuffer _dst) throws NdrException {
            handle.encode(_dst);
        }

        @Override
        public void decode_out(final NdrBuffer _src) throws NdrException {
            handle.decode(_src);
            retval = _src.dec_ndr_long();
        }
    }

    /**
     * LSA query information policy message.
     */
    public static class LsarQueryInformationPolicy extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x07;
        }

        /** Return value from the RPC call. */
        public int retval;
        /** Policy handle for the query. */
        public rpc.policy_handle handle;
        /** Information level to query. */
        public short level;
        /** Information object to populate. */
        public NdrObject info;

        /**
         * Creates a new LsarQueryInformationPolicy message.
         *
         * @param handle the policy handle
         * @param level the information level
         * @param info the information object
         */
        public LsarQueryInformationPolicy(final rpc.policy_handle handle, final short level, final NdrObject info) {
            this.handle = handle;
            this.level = level;
            this.info = info;
        }

        @Override
        public void encode_in(final NdrBuffer _dst) throws NdrException {
            handle.encode(_dst);
            _dst.enc_ndr_short(level);
        }

        @Override
        public void decode_out(final NdrBuffer _src) throws NdrException {
            final int _infop = _src.dec_ndr_long();
            if (_infop != 0) {
                _src.dec_ndr_short(); /* union discriminant */
                info.decode(_src);

            }
            retval = _src.dec_ndr_long();
        }
    }

    /**
     * LSA lookup SIDs message.
     */
    public static class LsarLookupSids extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x0f;
        }

        /** Return value from the RPC call. */
        public int retval;
        /** Policy handle for the LSA operation. */
        public rpc.policy_handle handle;
        /** Array of SIDs to lookup. */
        public LsarSidArray sids;
        /** Referenced domain list returned from lookup. */
        public LsarRefDomainList domains;
        /** Array of translated names. */
        public LsarTransNameArray names;
        /** Lookup level. */
        public short level;
        /** Count of SIDs to lookup. */
        public int count;

        /**
         * Creates a new LsarLookupSids message.
         *
         * @param handle the policy handle
         * @param sids the SIDs to lookup
         * @param domains the domain list to populate
         * @param names the names array to populate
         * @param level the lookup level
         * @param count the number of SIDs
         */
        public LsarLookupSids(final rpc.policy_handle handle, final LsarSidArray sids, final LsarRefDomainList domains,
                final LsarTransNameArray names, final short level, final int count) {
            this.handle = handle;
            this.sids = sids;
            this.domains = domains;
            this.names = names;
            this.level = level;
            this.count = count;
        }

        @Override
        public void encode_in(final NdrBuffer _dst) throws NdrException {
            handle.encode(_dst);
            sids.encode(_dst);
            names.encode(_dst);
            _dst.enc_ndr_short(level);
            _dst.enc_ndr_long(count);
        }

        @Override
        public void decode_out(final NdrBuffer _src) throws NdrException {
            final int _domainsp = _src.dec_ndr_long();
            if (_domainsp != 0) {
                if (domains == null) { /* YOYOYO */
                    domains = new LsarRefDomainList();
                }
                domains.decode(_src);

            }
            names.decode(_src);
            count = _src.dec_ndr_long();
            retval = _src.dec_ndr_long();
        }
    }

    /**
     * LSA open policy version 2 message.
     */
    public static class LsarOpenPolicy2 extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x2c;
        }

        /** Return value from the RPC call. */
        public int retval;
        /** Name of the system to connect to. */
        public String system_name;
        /** Object attributes for the policy. */
        public LsarObjectAttributes object_attributes;
        /** Desired access rights. */
        public int desired_access;
        /** Policy handle returned by the operation. */
        public rpc.policy_handle policy_handle;

        /**
         * Creates a new LsarOpenPolicy2 message.
         *
         * @param system_name the system name
         * @param object_attributes the object attributes
         * @param desired_access the desired access rights
         * @param policy_handle the policy handle to populate
         */
        public LsarOpenPolicy2(final String system_name, final LsarObjectAttributes object_attributes, final int desired_access,
                final rpc.policy_handle policy_handle) {
            this.system_name = system_name;
            this.object_attributes = object_attributes;
            this.desired_access = desired_access;
            this.policy_handle = policy_handle;
        }

        @Override
        public void encode_in(final NdrBuffer _dst) throws NdrException {
            _dst.enc_ndr_referent(system_name, 1);
            if (system_name != null) {
                _dst.enc_ndr_string(system_name);

            }
            object_attributes.encode(_dst);
            _dst.enc_ndr_long(desired_access);
        }

        @Override
        public void decode_out(final NdrBuffer _src) throws NdrException {
            policy_handle.decode(_src);
            retval = _src.dec_ndr_long();
        }
    }

    /**
     * LSA query information policy version 2 message.
     */
    public static class LsarQueryInformationPolicy2 extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x2e;
        }

        /** Return value from the RPC call. */
        public int retval;
        /** Policy handle for the query. */
        public rpc.policy_handle handle;
        /** Information level to query. */
        public short level;
        /** Information object to populate. */
        public NdrObject info;

        /**
         * Creates a new LsarQueryInformationPolicy2 message.
         *
         * @param handle the policy handle
         * @param level the information level
         * @param info the information object
         */
        public LsarQueryInformationPolicy2(final rpc.policy_handle handle, final short level, final NdrObject info) {
            this.handle = handle;
            this.level = level;
            this.info = info;
        }

        @Override
        public void encode_in(final NdrBuffer _dst) throws NdrException {
            handle.encode(_dst);
            _dst.enc_ndr_short(level);
        }

        @Override
        public void decode_out(final NdrBuffer _src) throws NdrException {
            final int _infop = _src.dec_ndr_long();
            if (_infop != 0) {
                _src.dec_ndr_short(); /* union discriminant */
                info.decode(_src);

            }
            retval = _src.dec_ndr_long();
        }
    }
}
