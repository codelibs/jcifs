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
package org.codelibs.jcifs.smb.internal.witness;

import org.codelibs.jcifs.smb.dcerpc.ndr.NdrBuffer;
import org.codelibs.jcifs.smb.dcerpc.ndr.NdrException;

/**
 * WitnessHeartbeat RPC message implementation for MS-SWN specification.
 * This message is used to send periodic heartbeats to maintain witness registrations.
 */
public class WitnessHeartbeatMessage extends WitnessRpcMessage {

    // Input parameters for WitnessHeartbeat
    private byte[] contextHandle;
    private long sequenceNumber;

    // Output parameters for WitnessHeartbeat
    private long responseSequenceNumber;
    private long heartbeatInterval;

    /**
     * Creates a new WitnessHeartbeat RPC message.
     */
    public WitnessHeartbeatMessage() {
        super(WITNESS_HEARTBEAT);
        this.contextHandle = new byte[20];
        this.sequenceNumber = 0;
        this.responseSequenceNumber = 0;
        this.heartbeatInterval = 0;
    }

    /**
     * Creates a new WitnessHeartbeat RPC message with the specified parameters.
     *
     * @param contextHandle the context handle from registration
     * @param sequenceNumber the sequence number for this heartbeat
     */
    public WitnessHeartbeatMessage(byte[] contextHandle, long sequenceNumber) {
        super(WITNESS_HEARTBEAT);
        this.contextHandle = contextHandle != null ? contextHandle.clone() : new byte[20];
        this.sequenceNumber = sequenceNumber;
        this.responseSequenceNumber = 0;
        this.heartbeatInterval = 0;
    }

    /**
     * Sets the context handle for the heartbeat.
     *
     * @param contextHandle the context handle from registration
     */
    public void setContextHandle(byte[] contextHandle) {
        this.contextHandle = contextHandle != null ? contextHandle.clone() : null;
    }

    /**
     * Gets the context handle.
     *
     * @return the context handle
     */
    public byte[] getContextHandle() {
        return contextHandle != null ? contextHandle.clone() : null;
    }

    /**
     * Sets the sequence number for this heartbeat.
     * The sequence number should be incremented for each heartbeat request.
     *
     * @param sequenceNumber the sequence number
     */
    public void setSequenceNumber(long sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    /**
     * Gets the sequence number.
     *
     * @return the sequence number
     */
    public long getSequenceNumber() {
        return sequenceNumber;
    }

    /**
     * Gets the response sequence number returned by the server.
     * This should match the request sequence number in a successful response.
     *
     * @return the response sequence number
     */
    public long getResponseSequenceNumber() {
        return responseSequenceNumber;
    }

    /**
     * Sets the response sequence number.
     *
     * @param responseSequenceNumber the response sequence number
     */
    public void setResponseSequenceNumber(long responseSequenceNumber) {
        this.responseSequenceNumber = responseSequenceNumber;
    }

    /**
     * Gets the heartbeat interval recommended by the server (in milliseconds).
     * The client can use this to adjust the heartbeat frequency.
     *
     * @return the heartbeat interval in milliseconds
     */
    public long getHeartbeatInterval() {
        return heartbeatInterval;
    }

    /**
     * Sets the heartbeat interval.
     *
     * @param heartbeatInterval the heartbeat interval in milliseconds
     */
    public void setHeartbeatInterval(long heartbeatInterval) {
        this.heartbeatInterval = heartbeatInterval;
    }

    /**
     * Validates that the heartbeat response is correct.
     * The response sequence number should match the request sequence number.
     *
     * @return true if the response is valid
     */
    public boolean isValidResponse() {
        return isSuccess() && responseSequenceNumber == sequenceNumber;
    }

    @Override
    protected void encodeWitnessParameters(NdrBuffer buf) throws NdrException {
        // Encode input parameters for WitnessHeartbeat

        // Context handle (20 bytes)
        if (contextHandle != null) {
            buf.writeOctetArray(contextHandle, 0, Math.min(contextHandle.length, 20));
            // Pad with zeros if context handle is shorter than 20 bytes
            for (int i = contextHandle.length; i < 20; i++) {
                buf.enc_ndr_small(0);
            }
        } else {
            // Write 20 zero bytes for null context handle
            for (int i = 0; i < 20; i++) {
                buf.enc_ndr_small(0);
            }
        }

        // Sequence number (64-bit)
        buf.enc_ndr_hyper(sequenceNumber);
    }

    @Override
    protected void decodeWitnessParameters(NdrBuffer buf) throws NdrException {
        // Decode output parameters for WitnessHeartbeat

        // Response sequence number (64-bit)
        responseSequenceNumber = buf.dec_ndr_hyper();

        // Heartbeat interval (64-bit, in 100-nanosecond intervals)
        // Convert from FILETIME intervals to milliseconds
        long filetimeInterval = buf.dec_ndr_hyper();
        heartbeatInterval = filetimeInterval / 10000; // Convert to milliseconds
    }
}