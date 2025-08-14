package jcifs.smb1.dcerpc.msrpc;

import jcifs.smb1.dcerpc.DcerpcMessage;
import jcifs.smb1.dcerpc.rpc;
import jcifs.smb1.dcerpc.ndr.NdrBuffer;
import jcifs.smb1.dcerpc.ndr.NdrException;
import jcifs.smb1.dcerpc.ndr.NdrObject;
import jcifs.smb1.dcerpc.ndr.NdrSmall;

public class lsarpc {

    public static String getSyntax() {
        return "12345778-1234-abcd-ef00-0123456789ab:0.0";
    }

    public static class LsarQosInfo extends NdrObject {

        public int length;
        public short impersonation_level;
        public byte context_mode;
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

    public static class LsarObjectAttributes extends NdrObject {

        public int length;
        public NdrSmall root_directory;
        public rpc.unicode_string object_name;
        public int attributes;
        public int security_descriptor;
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

    public static class LsarDomainInfo extends NdrObject {

        public rpc.unicode_string name;
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

    public static class LsarDnsDomainInfo extends NdrObject {

        public rpc.unicode_string name;
        public rpc.unicode_string dns_domain;
        public rpc.unicode_string dns_forest;
        public rpc.uuid_t domain_guid;
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

    public static final int POLICY_INFO_AUDIT_EVENTS = 2;
    public static final int POLICY_INFO_PRIMARY_DOMAIN = 3;
    public static final int POLICY_INFO_ACCOUNT_DOMAIN = 5;
    public static final int POLICY_INFO_SERVER_ROLE = 6;
    public static final int POLICY_INFO_MODIFICATION = 9;
    public static final int POLICY_INFO_DNS_DOMAIN = 12;

    public static class LsarSidPtr extends NdrObject {

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

    public static class LsarSidArray extends NdrObject {

        public int num_sids;
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

    public static final int SID_NAME_USE_NONE = 0;
    public static final int SID_NAME_USER = 1;
    public static final int SID_NAME_DOM_GRP = 2;
    public static final int SID_NAME_DOMAIN = 3;
    public static final int SID_NAME_ALIAS = 4;
    public static final int SID_NAME_WKN_GRP = 5;
    public static final int SID_NAME_DELETED = 6;
    public static final int SID_NAME_INVALID = 7;
    public static final int SID_NAME_UNKNOWN = 8;

    public static class LsarTranslatedSid extends NdrObject {

        public int sid_type;
        public int rid;
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

    public static class LsarTransSidArray extends NdrObject {

        public int count;
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

    public static class LsarTrustInformation extends NdrObject {

        public rpc.unicode_string name;
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

    public static class LsarRefDomainList extends NdrObject {

        public int count;
        public LsarTrustInformation[] domains;
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

    public static class LsarTranslatedName extends NdrObject {

        public short sid_type;
        public rpc.unicode_string name;
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

    public static class LsarTransNameArray extends NdrObject {

        public int count;
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

    public static class LsarClose extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x00;
        }

        public int retval;
        public rpc.policy_handle handle;

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

    public static class LsarQueryInformationPolicy extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x07;
        }

        public int retval;
        public rpc.policy_handle handle;
        public short level;
        public NdrObject info;

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

    public static class LsarLookupSids extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x0f;
        }

        public int retval;
        public rpc.policy_handle handle;
        public LsarSidArray sids;
        public LsarRefDomainList domains;
        public LsarTransNameArray names;
        public short level;
        public int count;

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

    public static class LsarOpenPolicy2 extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x2c;
        }

        public int retval;
        public String system_name;
        public LsarObjectAttributes object_attributes;
        public int desired_access;
        public rpc.policy_handle policy_handle;

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

    public static class LsarQueryInformationPolicy2 extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x2e;
        }

        public int retval;
        public rpc.policy_handle handle;
        public short level;
        public NdrObject info;

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
