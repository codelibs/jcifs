/* org.codelibs.jcifs.smb msrpc client library in Java
 * Copyright (C) 2006  "Michael B. Allen" <jcifs at samba dot org>
 *                     "Eric Glass" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb1.dcerpc;

import org.codelibs.jcifs.smb1.dcerpc.ndr.NdrBuffer;
import org.codelibs.jcifs.smb1.dcerpc.ndr.NdrException;
import org.codelibs.jcifs.smb1.dcerpc.ndr.NdrObject;

/**
 * Abstract base class for DCERPC messages.
 * This class provides common functionality for all DCE/RPC message types in SMB1 protocol.
 */
public abstract class DcerpcMessage extends NdrObject implements DcerpcConstants {

    /**
     * Default constructor for DcerpcMessage.
     * Initializes the DCE/RPC message structure for SMB1 protocol.
     */
    protected DcerpcMessage() {
        // Default constructor
    }

    /**
     * The packet type of this DCERPC message
     */
    protected int ptype = -1;
    /**
     * The flags for this DCERPC message
     */
    protected int flags = 0;
    /**
     * The total length of this DCERPC message
     */
    protected int length = 0;
    /**
     * The call ID for matching requests and responses
     */
    protected int call_id = 0;
    /**
     * The allocation hint for buffer sizing
     */
    protected int alloc_hint = 0;
    /**
     * The result code of the DCERPC operation
     */
    protected int result = 0;

    /**
     * Checks if a specific flag is set
     * @param flag the flag to check
     * @return true if the flag is set, false otherwise
     */
    public boolean isFlagSet(final int flag) {
        return (flags & flag) == flag;
    }

    /**
     * Unsets a specific flag
     * @param flag the flag to unset
     */
    public void unsetFlag(final int flag) {
        flags &= ~flag;
    }

    /**
     * Sets a specific flag
     * @param flag the flag to set
     */
    public void setFlag(final int flag) {
        flags |= flag;
    }

    /**
     * Get the result of the DCERPC call.
     * @return result exception if the call failed, null otherwise
     */
    public DcerpcException getResult() {
        if (result != 0) {
            return new DcerpcException(result);
        }
        return null;
    }

    void encode_header(final NdrBuffer buf) {
        buf.enc_ndr_small(5); /* RPC version */
        buf.enc_ndr_small(0); /* minor version */
        buf.enc_ndr_small(ptype);
        buf.enc_ndr_small(flags);
        buf.enc_ndr_long(0x00000010); /* Little-endian / ASCII / IEEE */
        buf.enc_ndr_short(length);
        buf.enc_ndr_short(0); /* length of auth_value */
        buf.enc_ndr_long(call_id);
    }

    void decode_header(final NdrBuffer buf) throws NdrException {
        /* RPC major / minor version */
        if (buf.dec_ndr_small() != 5 || buf.dec_ndr_small() != 0) {
            throw new NdrException("DCERPC version not supported");
        }
        ptype = buf.dec_ndr_small();
        flags = buf.dec_ndr_small();
        if (buf.dec_ndr_long() != 0x00000010) { /* Little-endian / ASCII / IEEE */
            throw new NdrException("Data representation not supported");
        }
        length = buf.dec_ndr_short();
        if (buf.dec_ndr_short() != 0) {
            throw new NdrException("DCERPC authentication not supported");
        }
        call_id = buf.dec_ndr_long();
    }

    @Override
    public void encode(final NdrBuffer buf) throws NdrException {
        final int start = buf.getIndex();
        int alloc_hint_index = 0;

        buf.advance(16); /* momentarily skip header */
        if (ptype == 0) { /* Request */
            alloc_hint_index = buf.getIndex();
            buf.enc_ndr_long(0); /* momentarily skip alloc hint */
            buf.enc_ndr_short(0); /* context id */
            buf.enc_ndr_short(getOpnum());
        }

        encode_in(buf);
        length = buf.getIndex() - start;

        if (ptype == 0) {
            buf.setIndex(alloc_hint_index);
            alloc_hint = length - alloc_hint_index;
            buf.enc_ndr_long(alloc_hint);
        }

        buf.setIndex(start);
        encode_header(buf);
        buf.setIndex(start + length);
    }

    @Override
    public void decode(final NdrBuffer buf) throws NdrException {
        decode_header(buf);

        if (ptype != 12 && ptype != 2 && ptype != 3 && ptype != 13) {
            throw new NdrException("Unexpected ptype: " + ptype);
        }

        if (ptype == 2 || ptype == 3) { /* Response or Fault */
            alloc_hint = buf.dec_ndr_long();
            buf.dec_ndr_short(); /* context id */
            buf.dec_ndr_short(); /* cancel count */
        }
        if (ptype == 3 || ptype == 13) { /* Fault */
            result = buf.dec_ndr_long();
        } else { /* Bind_ack or Response */
            decode_out(buf);
        }
    }

    /**
     * Get the operation number for this DCERPC message.
     * @return the operation number
     */
    public abstract int getOpnum();

    /**
     * Encode the input parameters for this DCERPC message.
     * @param buf the buffer to encode into
     * @throws NdrException if encoding fails
     */
    public abstract void encode_in(NdrBuffer buf) throws NdrException;

    /**
     * Decode the output parameters from this DCERPC message.
     * @param buf the buffer to decode from
     * @throws NdrException if decoding fails
     */
    public abstract void decode_out(NdrBuffer buf) throws NdrException;
}
