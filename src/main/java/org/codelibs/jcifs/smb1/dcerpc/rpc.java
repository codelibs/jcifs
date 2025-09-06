package org.codelibs.jcifs.smb1.dcerpc;

import org.codelibs.jcifs.smb1.dcerpc.ndr.NdrBuffer;
import org.codelibs.jcifs.smb1.dcerpc.ndr.NdrException;
import org.codelibs.jcifs.smb1.dcerpc.ndr.NdrObject;

/**
 * RPC data structure definitions for DCE/RPC protocol support.
 * This class contains NDR (Network Data Representation) encodable/decodable structures
 * used in DCE/RPC communications.
 */
public class rpc {

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private rpc() {
        // Utility class
    }

    /**
     * UUID (Universally Unique Identifier) structure for DCE/RPC.
     * Represents a 128-bit UUID as defined by DCE/RPC specification.
     */
    public static class uuid_t extends NdrObject {

        /**
         * Default constructor for uuid_t.
         */
        public uuid_t() {
            // Default constructor
        }

        /**
         * The low field of the timestamp.
         */
        public int time_low;
        /**
         * The middle field of the timestamp.
         */
        public short time_mid;
        /**
         * The high field of the timestamp multiplexed with the version number.
         */
        public short time_hi_and_version;
        /**
         * The high field of the clock sequence multiplexed with the variant.
         */
        public byte clock_seq_hi_and_reserved;
        /**
         * The low field of the clock sequence.
         */
        public byte clock_seq_low;
        /**
         * The spatially unique node identifier (6 bytes).
         */
        public byte[] node;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(time_low);
            _dst.enc_ndr_short(time_mid);
            _dst.enc_ndr_short(time_hi_and_version);
            _dst.enc_ndr_small(clock_seq_hi_and_reserved);
            _dst.enc_ndr_small(clock_seq_low);
            final int _nodes = 6;
            final int _nodei = _dst.index;
            _dst.advance(1 * _nodes);

            _dst = _dst.derive(_nodei);
            for (int _i = 0; _i < _nodes; _i++) {
                _dst.enc_ndr_small(node[_i]);
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            time_low = _src.dec_ndr_long();
            time_mid = (short) _src.dec_ndr_short();
            time_hi_and_version = (short) _src.dec_ndr_short();
            clock_seq_hi_and_reserved = (byte) _src.dec_ndr_small();
            clock_seq_low = (byte) _src.dec_ndr_small();
            final int _nodes = 6;
            final int _nodei = _src.index;
            _src.advance(1 * _nodes);

            if (node == null) {
                if (_nodes < 0 || _nodes > 0xFFFF) {
                    throw new NdrException(NdrException.INVALID_CONFORMANCE);
                }
                node = new byte[_nodes];
            }
            _src = _src.derive(_nodei);
            for (int _i = 0; _i < _nodes; _i++) {
                node[_i] = (byte) _src.dec_ndr_small();
            }
        }
    }

    /**
     * Policy handle structure for DCE/RPC operations.
     * Represents a handle to a policy object on the server.
     */
    public static class policy_handle extends NdrObject {

        /**
         * Default constructor for policy_handle.
         */
        public policy_handle() {
            // Default constructor
        }

        /**
         * The type of the policy handle.
         */
        public int type;
        /**
         * The UUID associated with this policy handle.
         */
        public uuid_t uuid;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(type);
            _dst.enc_ndr_long(uuid.time_low);
            _dst.enc_ndr_short(uuid.time_mid);
            _dst.enc_ndr_short(uuid.time_hi_and_version);
            _dst.enc_ndr_small(uuid.clock_seq_hi_and_reserved);
            _dst.enc_ndr_small(uuid.clock_seq_low);
            final int _uuid_nodes = 6;
            final int _uuid_nodei = _dst.index;
            _dst.advance(1 * _uuid_nodes);

            _dst = _dst.derive(_uuid_nodei);
            for (int _i = 0; _i < _uuid_nodes; _i++) {
                _dst.enc_ndr_small(uuid.node[_i]);
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            type = _src.dec_ndr_long();
            _src.align(4);
            if (uuid == null) {
                uuid = new uuid_t();
            }
            uuid.time_low = _src.dec_ndr_long();
            uuid.time_mid = (short) _src.dec_ndr_short();
            uuid.time_hi_and_version = (short) _src.dec_ndr_short();
            uuid.clock_seq_hi_and_reserved = (byte) _src.dec_ndr_small();
            uuid.clock_seq_low = (byte) _src.dec_ndr_small();
            final int _uuid_nodes = 6;
            final int _uuid_nodei = _src.index;
            _src.advance(1 * _uuid_nodes);

            if (uuid.node == null) {
                if (_uuid_nodes < 0 || _uuid_nodes > 0xFFFF) {
                    throw new NdrException(NdrException.INVALID_CONFORMANCE);
                }
                uuid.node = new byte[_uuid_nodes];
            }
            _src = _src.derive(_uuid_nodei);
            for (int _i = 0; _i < _uuid_nodes; _i++) {
                uuid.node[_i] = (byte) _src.dec_ndr_small();
            }
        }
    }

    /**
     * Unicode string structure for DCE/RPC.
     * Represents a counted Unicode string as used in RPC protocols.
     */
    public static class unicode_string extends NdrObject {

        /**
         * Default constructor for unicode_string.
         */
        public unicode_string() {
            // Default constructor
        }

        /**
         * The actual length of the string in bytes.
         */
        public short length;
        /**
         * The maximum allocated length of the string in bytes.
         */
        public short maximum_length;
        /**
         * The buffer containing the Unicode characters.
         */
        public short[] buffer;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_short(length);
            _dst.enc_ndr_short(maximum_length);
            _dst.enc_ndr_referent(buffer, 1);

            if (buffer != null) {
                _dst = _dst.deferred;
                final int _bufferl = length / 2;
                final int _buffers = maximum_length / 2;
                _dst.enc_ndr_long(_buffers);
                _dst.enc_ndr_long(0);
                _dst.enc_ndr_long(_bufferl);
                final int _bufferi = _dst.index;
                _dst.advance(2 * _bufferl);

                _dst = _dst.derive(_bufferi);
                for (int _i = 0; _i < _bufferl; _i++) {
                    _dst.enc_ndr_short(buffer[_i]);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            length = (short) _src.dec_ndr_short();
            maximum_length = (short) _src.dec_ndr_short();
            final int _bufferp = _src.dec_ndr_long();

            if (_bufferp != 0) {
                _src = _src.deferred;
                final int _buffers = _src.dec_ndr_long();
                _src.dec_ndr_long();
                final int _bufferl = _src.dec_ndr_long();
                final int _bufferi = _src.index;
                _src.advance(2 * _bufferl);

                if (buffer == null) {
                    if (_buffers < 0 || _buffers > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    buffer = new short[_buffers];
                }
                _src = _src.derive(_bufferi);
                for (int _i = 0; _i < _bufferl; _i++) {
                    buffer[_i] = (short) _src.dec_ndr_short();
                }
            }
        }
    }

    /**
     * Security Identifier (SIDObject) structure for DCE/RPC.
     * Represents a Windows security identifier used in RPC operations.
     */
    public static class sid_t extends NdrObject {

        /**
         * Default constructor for sid_t.
         */
        public sid_t() {
            // Default constructor
        }

        /**
         * The revision level of the SIDObject structure.
         */
        public byte revision;
        /**
         * The number of sub-authorities in this SIDObject.
         */
        public byte sub_authority_count;
        /**
         * The identifier authority value (6 bytes).
         */
        public byte[] identifier_authority;
        /**
         * Array of sub-authority values.
         */
        public int[] sub_authority;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            final int _sub_authoritys = sub_authority_count;
            _dst.enc_ndr_long(_sub_authoritys);
            _dst.enc_ndr_small(revision);
            _dst.enc_ndr_small(sub_authority_count);
            final int _identifier_authoritys = 6;
            final int _identifier_authorityi = _dst.index;
            _dst.advance(1 * _identifier_authoritys);
            final int _sub_authorityi = _dst.index;
            _dst.advance(4 * _sub_authoritys);

            _dst = _dst.derive(_identifier_authorityi);
            for (int _i = 0; _i < _identifier_authoritys; _i++) {
                _dst.enc_ndr_small(identifier_authority[_i]);
            }
            _dst = _dst.derive(_sub_authorityi);
            for (int _i = 0; _i < _sub_authoritys; _i++) {
                _dst.enc_ndr_long(sub_authority[_i]);
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            final int _sub_authoritys = _src.dec_ndr_long();
            revision = (byte) _src.dec_ndr_small();
            sub_authority_count = (byte) _src.dec_ndr_small();
            final int _identifier_authoritys = 6;
            final int _identifier_authorityi = _src.index;
            _src.advance(1 * _identifier_authoritys);
            final int _sub_authorityi = _src.index;
            _src.advance(4 * _sub_authoritys);

            if (identifier_authority == null) {
                if (_identifier_authoritys < 0 || _identifier_authoritys > 0xFFFF) {
                    throw new NdrException(NdrException.INVALID_CONFORMANCE);
                }
                identifier_authority = new byte[_identifier_authoritys];
            }
            _src = _src.derive(_identifier_authorityi);
            for (int _i = 0; _i < _identifier_authoritys; _i++) {
                identifier_authority[_i] = (byte) _src.dec_ndr_small();
            }
            if (sub_authority == null) {
                if (_sub_authoritys < 0 || _sub_authoritys > 0xFFFF) {
                    throw new NdrException(NdrException.INVALID_CONFORMANCE);
                }
                sub_authority = new int[_sub_authoritys];
            }
            _src = _src.derive(_sub_authorityi);
            for (int _i = 0; _i < _sub_authoritys; _i++) {
                sub_authority[_i] = _src.dec_ndr_long();
            }
        }
    }
}
