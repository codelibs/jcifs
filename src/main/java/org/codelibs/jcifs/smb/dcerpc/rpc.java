package org.codelibs.jcifs.smb.dcerpc;

import org.codelibs.jcifs.smb.dcerpc.ndr.NdrBuffer;
import org.codelibs.jcifs.smb.dcerpc.ndr.NdrException;
import org.codelibs.jcifs.smb.dcerpc.ndr.NdrObject;

/**
 * RPC data structure definitions for DCE/RPC protocol support.
 * This class contains NDR (Network Data Representation) encodable/decodable structures
 * used in DCE/RPC communications including UUID, policy handles, unicode strings, and SIDs.
 */
@SuppressWarnings("all")
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

        /** The low field of the timestamp */
        public int time_low;
        /** The middle field of the timestamp */
        public short time_mid;
        /** The high field of the timestamp multiplexed with the version number */
        public short time_hi_and_version;
        /** The high field of the clock sequence multiplexed with the variant */
        public byte clock_seq_hi_and_reserved;
        /** The low field of the clock sequence */
        public byte clock_seq_low;
        /** The spatially unique node identifier */
        public byte[] node;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(this.time_low);
            _dst.enc_ndr_short(this.time_mid);
            _dst.enc_ndr_short(this.time_hi_and_version);
            _dst.enc_ndr_small(this.clock_seq_hi_and_reserved);
            _dst.enc_ndr_small(this.clock_seq_low);
            final int _nodes = 6;
            final int _nodei = _dst.index;
            _dst.advance(1 * _nodes);

            _dst = _dst.derive(_nodei);
            for (int _i = 0; _i < _nodes; _i++) {
                _dst.enc_ndr_small(this.node[_i]);
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            this.time_low = _src.dec_ndr_long();
            this.time_mid = (short) _src.dec_ndr_short();
            this.time_hi_and_version = (short) _src.dec_ndr_short();
            this.clock_seq_hi_and_reserved = (byte) _src.dec_ndr_small();
            this.clock_seq_low = (byte) _src.dec_ndr_small();
            final int _nodes = 6;
            final int _nodei = _src.index;
            _src.advance(1 * _nodes);

            if (this.node == null) {
                if (_nodes < 0 || _nodes > 0xFFFF) {
                    throw new NdrException(NdrException.INVALID_CONFORMANCE);
                }
                this.node = new byte[_nodes];
            }
            _src = _src.derive(_nodei);
            for (int _i = 0; _i < _nodes; _i++) {
                this.node[_i] = (byte) _src.dec_ndr_small();
            }
        }
    }

    /**
     * Policy handle structure for DCE/RPC operations.
     * Represents an opaque handle used to reference server-side resources.
     */
    public static class policy_handle extends NdrObject {

        /**
         * Default constructor for policy_handle.
         */
        public policy_handle() {
            // Default constructor
        }

        /** The type of the policy handle */
        public int type;
        /** The UUID associated with the policy handle */
        public uuid_t uuid;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(this.type);
            if (this.uuid == null) {
                throw new NdrException(NdrException.NO_NULL_REF);
            }
            _dst.enc_ndr_long(this.uuid.time_low);
            _dst.enc_ndr_short(this.uuid.time_mid);
            _dst.enc_ndr_short(this.uuid.time_hi_and_version);
            _dst.enc_ndr_small(this.uuid.clock_seq_hi_and_reserved);
            _dst.enc_ndr_small(this.uuid.clock_seq_low);
            final int _uuid_nodes = 6;
            final int _uuid_nodei = _dst.index;
            _dst.advance(1 * _uuid_nodes);

            _dst = _dst.derive(_uuid_nodei);
            for (int _i = 0; _i < _uuid_nodes; _i++) {
                _dst.enc_ndr_small(this.uuid.node[_i]);
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            this.type = _src.dec_ndr_long();
            _src.align(4);
            if (this.uuid == null) {
                this.uuid = new uuid_t();
            }
            this.uuid.time_low = _src.dec_ndr_long();
            this.uuid.time_mid = (short) _src.dec_ndr_short();
            this.uuid.time_hi_and_version = (short) _src.dec_ndr_short();
            this.uuid.clock_seq_hi_and_reserved = (byte) _src.dec_ndr_small();
            this.uuid.clock_seq_low = (byte) _src.dec_ndr_small();
            final int _uuid_nodes = 6;
            final int _uuid_nodei = _src.index;
            _src.advance(1 * _uuid_nodes);

            if (this.uuid.node == null) {
                if (_uuid_nodes < 0 || _uuid_nodes > 0xFFFF) {
                    throw new NdrException(NdrException.INVALID_CONFORMANCE);
                }
                this.uuid.node = new byte[_uuid_nodes];
            }
            _src = _src.derive(_uuid_nodei);
            for (int _i = 0; _i < _uuid_nodes; _i++) {
                this.uuid.node[_i] = (byte) _src.dec_ndr_small();
            }
        }
    }

    /**
     * Unicode string structure for DCE/RPC operations.
     * Represents a Unicode string with length information.
     */
    public static class unicode_string extends NdrObject {

        /**
         * Default constructor for unicode_string.
         */
        public unicode_string() {
            // Default constructor
        }

        /** The length of the string in bytes */
        public short length;
        /** The maximum length of the string buffer in bytes */
        public short maximum_length;
        /** The Unicode character buffer */
        public short[] buffer;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_short(this.length);
            _dst.enc_ndr_short(this.maximum_length);
            _dst.enc_ndr_referent(this.buffer, 1);

            if (this.buffer != null) {
                _dst = _dst.deferred;
                final int _bufferl = this.length / 2;
                final int _buffers = this.maximum_length / 2;
                _dst.enc_ndr_long(_buffers);
                _dst.enc_ndr_long(0);
                _dst.enc_ndr_long(_bufferl);
                final int _bufferi = _dst.index;
                _dst.advance(2 * _bufferl);

                _dst = _dst.derive(_bufferi);
                for (int _i = 0; _i < _bufferl; _i++) {
                    _dst.enc_ndr_short(this.buffer[_i]);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            this.length = (short) _src.dec_ndr_short();
            this.maximum_length = (short) _src.dec_ndr_short();
            final int _bufferp = _src.dec_ndr_long();

            if (_bufferp != 0) {
                _src = _src.deferred;
                final int _buffers = _src.dec_ndr_long();
                _src.dec_ndr_long();
                final int _bufferl = _src.dec_ndr_long();
                final int _bufferi = _src.index;
                _src.advance(2 * _bufferl);

                if (this.buffer == null) {
                    if (_buffers < 0 || _buffers > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    this.buffer = new short[_buffers];
                }
                _src = _src.derive(_bufferi);
                for (int _i = 0; _i < _bufferl; _i++) {
                    this.buffer[_i] = (short) _src.dec_ndr_short();
                }
            }
        }
    }

    /**
     * Security Identifier (SID) structure for DCE/RPC operations.
     * Represents a Windows security identifier used for access control.
     */
    public static class sid_t extends NdrObject {

        /**
         * Default constructor for sid_t.
         */
        public sid_t() {
            // Default constructor
        }

        /** The revision level of the SID structure */
        public byte revision;
        /** The number of sub-authorities in the SID */
        public byte sub_authority_count;
        /** The identifier authority value (6 bytes) */
        public byte[] identifier_authority;
        /** The array of sub-authority values */
        public int[] sub_authority;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            final int _sub_authoritys = this.sub_authority_count;
            _dst.enc_ndr_long(_sub_authoritys);
            _dst.enc_ndr_small(this.revision);
            _dst.enc_ndr_small(this.sub_authority_count);
            final int _identifier_authoritys = 6;
            final int _identifier_authorityi = _dst.index;
            _dst.advance(1 * _identifier_authoritys);
            final int _sub_authorityi = _dst.index;
            _dst.advance(4 * _sub_authoritys);

            _dst = _dst.derive(_identifier_authorityi);
            for (int _i = 0; _i < _identifier_authoritys; _i++) {
                _dst.enc_ndr_small(this.identifier_authority[_i]);
            }
            _dst = _dst.derive(_sub_authorityi);
            for (int _i = 0; _i < _sub_authoritys; _i++) {
                _dst.enc_ndr_long(this.sub_authority[_i]);
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            final int _sub_authoritys = _src.dec_ndr_long();
            this.revision = (byte) _src.dec_ndr_small();
            this.sub_authority_count = (byte) _src.dec_ndr_small();
            final int _identifier_authoritys = 6;
            final int _identifier_authorityi = _src.index;
            _src.advance(1 * _identifier_authoritys);
            final int _sub_authorityi = _src.index;
            _src.advance(4 * _sub_authoritys);

            if (this.identifier_authority == null) {
                if (_identifier_authoritys < 0 || _identifier_authoritys > 0xFFFF) {
                    throw new NdrException(NdrException.INVALID_CONFORMANCE);
                }
                this.identifier_authority = new byte[_identifier_authoritys];
            }
            _src = _src.derive(_identifier_authorityi);
            for (int _i = 0; _i < _identifier_authoritys; _i++) {
                this.identifier_authority[_i] = (byte) _src.dec_ndr_small();
            }
            if (this.sub_authority == null) {
                if (_sub_authoritys < 0 || _sub_authoritys > 0xFFFF) {
                    throw new NdrException(NdrException.INVALID_CONFORMANCE);
                }
                this.sub_authority = new int[_sub_authoritys];
            }
            _src = _src.derive(_sub_authorityi);
            for (int _i = 0; _i < _sub_authoritys; _i++) {
                this.sub_authority[_i] = _src.dec_ndr_long();
            }
        }
    }
}
