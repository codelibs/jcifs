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
 * WitnessUnregister RPC message implementation for MS-SWN specification.
 * This message is used to unregister from witness notifications.
 */
public class WitnessUnregisterMessage extends WitnessRpcMessage {

    // Input parameters for WitnessUnregister
    private byte[] contextHandle;

    /**
     * Creates a new WitnessUnregister RPC message.
     */
    public WitnessUnregisterMessage() {
        super(WITNESS_UNREGISTER);
        this.contextHandle = new byte[20]; // Standard DCE/RPC context handle size
    }

    /**
     * Creates a new WitnessUnregister RPC message with the specified context handle.
     *
     * @param contextHandle the context handle from registration
     */
    public WitnessUnregisterMessage(byte[] contextHandle) {
        super(WITNESS_UNREGISTER);
        this.contextHandle = contextHandle != null ? contextHandle.clone() : new byte[20];
    }

    /**
     * Sets the context handle for unregistration.
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

    @Override
    protected void encodeWitnessParameters(NdrBuffer buf) throws NdrException {
        // Encode input parameters for WitnessUnregister

        // Context handle (20 bytes) - this is both input and output (modified)
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
    }

    @Override
    protected void decodeWitnessParameters(NdrBuffer buf) throws NdrException {
        // Decode output parameters for WitnessUnregister

        // Context handle is modified by the server (typically zeroed out)
        if (contextHandle == null) {
            contextHandle = new byte[20];
        }
        buf.readOctetArray(contextHandle, 0, 20);
    }

    /**
     * Checks if the context handle has been invalidated (all zeros).
     * A successful unregistration typically results in a zeroed context handle.
     *
     * @return true if the context handle has been invalidated
     */
    public boolean isContextHandleInvalidated() {
        if (contextHandle == null) {
            return true;
        }

        for (byte b : contextHandle) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}