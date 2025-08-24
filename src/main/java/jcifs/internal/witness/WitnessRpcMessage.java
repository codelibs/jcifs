/*
 * © 2025 CodeLibs, Inc.
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
package jcifs.internal.witness;

import jcifs.dcerpc.DcerpcMessage;
import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;

/**
 * Base class for SMB Witness Protocol RPC messages as defined in MS-SWN specification.
 * This class extends DcerpcMessage to provide witness-specific RPC operations.
 */
public abstract class WitnessRpcMessage extends DcerpcMessage {

    // MS-SWN Witness Protocol Interface UUID and Version
    /** Witness Protocol Interface UUID from MS-SWN specification */
    public static final String WITNESS_INTERFACE_UUID = "ccd8c074-d0e5-4a40-92b4-d074faa6ba28";
    /** Witness Protocol major version number */
    public static final int WITNESS_INTERFACE_VERSION_MAJOR = 1;
    /** Witness Protocol minor version number */
    public static final int WITNESS_INTERFACE_VERSION_MINOR = 0;

    // MS-SWN RPC Operation Numbers
    /** WitnessRegister operation number */
    public static final int WITNESS_REGISTER = 0;
    /** WitnessUnregister operation number */
    public static final int WITNESS_UNREGISTER = 1;
    /** WitnessAsyncNotify operation number */
    public static final int WITNESS_ASYNC_NOTIFY = 2;
    /** Witness heartbeat operation number */
    public static final int WITNESS_HEARTBEAT = 3;

    // Common return codes from MS-SWN specification
    /** Operation completed successfully */
    public static final int ERROR_SUCCESS = 0x00000000;
    /** Invalid parameter was passed to the operation */
    public static final int ERROR_INVALID_PARAMETER = 0x00000057;
    /** Buffer provided is insufficient */
    public static final int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;
    /** Operation is not supported */
    public static final int ERROR_NOT_SUPPORTED = 0x00000032;
    /** Access denied to perform the operation */
    public static final int ERROR_ACCESS_DENIED = 0x00000005;
    /** Invalid state for the operation */
    public static final int ERROR_INVALID_STATE = 0x0000139F;

    /** Return code from the RPC operation */
    protected int returnCode = ERROR_SUCCESS;
    private int opnum;

    /**
     * Creates a new witness RPC message with the specified operation number.
     *
     * @param opnum the operation number for this message
     */
    protected WitnessRpcMessage(int opnum) {
        ptype = 0; // REQUEST
        flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
        this.opnum = opnum;
    }

    @Override
    public int getOpnum() {
        return opnum;
    }

    /**
     * Gets the return code from the RPC operation.
     *
     * @return the return code
     */
    public int getReturnCode() {
        return returnCode;
    }

    /**
     * Sets the return code for the RPC operation.
     *
     * @param returnCode the return code to set
     */
    public void setReturnCode(int returnCode) {
        this.returnCode = returnCode;
    }

    /**
     * Checks if the RPC operation was successful.
     *
     * @return true if successful (return code is ERROR_SUCCESS)
     */
    public boolean isSuccess() {
        return returnCode == ERROR_SUCCESS;
    }

    /**
     * Gets the error message for the current return code.
     *
     * @return a human-readable error message
     */
    public String getErrorMessage() {
        switch (returnCode) {
        case ERROR_SUCCESS:
            return "Success";
        case ERROR_INVALID_PARAMETER:
            return "Invalid parameter";
        case ERROR_INSUFFICIENT_BUFFER:
            return "Insufficient buffer";
        case ERROR_NOT_SUPPORTED:
            return "Operation not supported";
        case ERROR_ACCESS_DENIED:
            return "Access denied";
        case ERROR_INVALID_STATE:
            return "Invalid state";
        default:
            return "Unknown error: 0x" + Integer.toHexString(returnCode);
        }
    }

    /**
     * Encodes the witness RPC message parameters to NDR format.
     * Subclasses must implement this method to encode their specific parameters.
     *
     * @param buf the NDR buffer to encode into
     * @throws NdrException if encoding fails
     */
    protected abstract void encodeWitnessParameters(NdrBuffer buf) throws NdrException;

    /**
     * Decodes the witness RPC message parameters from NDR format.
     * Subclasses must implement this method to decode their specific parameters.
     *
     * @param buf the NDR buffer to decode from
     * @throws NdrException if decoding fails
     */
    protected abstract void decodeWitnessParameters(NdrBuffer buf) throws NdrException;

    @Override
    public void encode_in(NdrBuffer buf) throws NdrException {
        encodeWitnessParameters(buf);
    }

    @Override
    public void decode_out(NdrBuffer buf) throws NdrException {
        decodeWitnessParameters(buf);
        // The return code is always the last 4 bytes in MS-SWN responses
        returnCode = buf.dec_ndr_long();
    }
}