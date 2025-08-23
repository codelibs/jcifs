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

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;

import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;

/**
 * WitnessRegister RPC message implementation for MS-SWN specification.
 * This message is used to register for witness notifications on a specific resource.
 */
public class WitnessRegisterMessage extends WitnessRpcMessage {

    // Input parameters for WitnessRegister
    private WitnessVersion version;
    private String netName;
    private String shareName;
    private String ipAddress;
    private String clientComputerName;
    private int flags;
    private int timeout;

    // Output parameters for WitnessRegister
    private byte[] contextHandle;

    /**
     * Creates a new WitnessRegister RPC message.
     */
    public WitnessRegisterMessage() {
        super(WITNESS_REGISTER);
        this.contextHandle = new byte[20]; // Standard DCE/RPC context handle size
    }

    /**
     * Sets the witness protocol version.
     *
     * @param version the witness protocol version
     */
    public void setVersion(WitnessVersion version) {
        this.version = version;
    }

    /**
     * Gets the witness protocol version.
     *
     * @return the witness protocol version
     */
    public WitnessVersion getVersion() {
        return version;
    }

    /**
     * Sets the network name (server name).
     *
     * @param netName the network name
     */
    public void setNetName(String netName) {
        this.netName = netName;
    }

    /**
     * Gets the network name.
     *
     * @return the network name
     */
    public String getNetName() {
        return netName;
    }

    /**
     * Sets the share name to monitor.
     *
     * @param shareName the share name
     */
    public void setShareName(String shareName) {
        this.shareName = shareName;
    }

    /**
     * Gets the share name.
     *
     * @return the share name
     */
    public String getShareName() {
        return shareName;
    }

    /**
     * Sets the IP address of the client.
     *
     * @param ipAddress the IP address
     */
    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    /**
     * Sets the IP address from an InetAddress.
     *
     * @param address the InetAddress
     */
    public void setIpAddress(InetAddress address) {
        if (address != null) {
            this.ipAddress = address.getHostAddress();
        }
    }

    /**
     * Gets the IP address.
     *
     * @return the IP address
     */
    public String getIpAddress() {
        return ipAddress;
    }

    /**
     * Sets the client computer name.
     *
     * @param clientComputerName the client computer name
     */
    public void setClientComputerName(String clientComputerName) {
        this.clientComputerName = clientComputerName;
    }

    /**
     * Gets the client computer name.
     *
     * @return the client computer name
     */
    public String getClientComputerName() {
        return clientComputerName;
    }

    /**
     * Sets the registration flags.
     *
     * @param flags the registration flags
     */
    public void setFlags(int flags) {
        this.flags = flags;
    }

    /**
     * Gets the registration flags.
     *
     * @return the registration flags
     */
    public int getFlags() {
        return flags;
    }

    /**
     * Sets the timeout value in seconds.
     *
     * @param timeout the timeout value
     */
    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    /**
     * Gets the timeout value.
     *
     * @return the timeout value
     */
    public int getTimeout() {
        return timeout;
    }

    /**
     * Gets the context handle returned by the server.
     *
     * @return the context handle
     */
    public byte[] getContextHandle() {
        return contextHandle != null ? contextHandle.clone() : null;
    }

    /**
     * Sets the context handle.
     *
     * @param contextHandle the context handle
     */
    public void setContextHandle(byte[] contextHandle) {
        this.contextHandle = contextHandle != null ? contextHandle.clone() : null;
    }

    @Override
    protected void encodeWitnessParameters(NdrBuffer buf) throws NdrException {
        // Encode input parameters for WitnessRegister

        // Version (WITNESS_VERSION structure)
        if (version != null) {
            buf.enc_ndr_long(version.getMajorVersion());
            buf.enc_ndr_long(version.getMinorVersion());
        } else {
            buf.enc_ndr_long(WITNESS_INTERFACE_VERSION_MAJOR);
            buf.enc_ndr_long(WITNESS_INTERFACE_VERSION_MINOR);
        }

        // NetName (wide string pointer)
        encodeWideStringPointer(buf, netName);

        // ShareName (wide string pointer, optional)
        encodeWideStringPointer(buf, shareName);

        // IpAddress (wide string pointer, optional)
        encodeWideStringPointer(buf, ipAddress);

        // ClientComputerName (wide string pointer)
        encodeWideStringPointer(buf, clientComputerName);

        // Flags
        buf.enc_ndr_long(flags);

        // Timeout
        buf.enc_ndr_long(timeout);
    }

    @Override
    protected void decodeWitnessParameters(NdrBuffer buf) throws NdrException {
        // Decode output parameters for WitnessRegister

        // Context handle (20 bytes)
        if (contextHandle == null) {
            contextHandle = new byte[20];
        }
        buf.readOctetArray(contextHandle, 0, 20);
    }

    /**
     * Encodes a wide string pointer in NDR format.
     *
     * @param buf the NDR buffer
     * @param str the string to encode (can be null)
     * @throws NdrException if encoding fails
     */
    private void encodeWideStringPointer(NdrBuffer buf, String str) throws NdrException {
        if (str == null || str.isEmpty()) {
            buf.enc_ndr_long(0); // NULL pointer
        } else {
            buf.enc_ndr_long(1); // Non-NULL pointer

            // Convert to UTF-16LE (wide string)
            byte[] wideBytes = str.getBytes(StandardCharsets.UTF_16LE);
            int charCount = str.length();

            // NDR string structure: MaximumCount, Offset, ActualCount, then data
            buf.enc_ndr_long(charCount + 1); // MaximumCount (including null terminator)
            buf.enc_ndr_long(0); // Offset
            buf.enc_ndr_long(charCount + 1); // ActualCount (including null terminator)

            // String data in UTF-16LE
            buf.writeOctetArray(wideBytes, 0, wideBytes.length);
            buf.enc_ndr_short(0); // Wide null terminator

            // Pad to 4-byte boundary
            int padding = (4 - ((wideBytes.length + 2) % 4)) % 4;
            for (int i = 0; i < padding; i++) {
                buf.enc_ndr_small(0);
            }
        }
    }

    /**
     * Decodes a wide string pointer from NDR format.
     *
     * @param buf the NDR buffer
     * @return the decoded string (or null if NULL pointer)
     * @throws NdrException if decoding fails
     */
    private String decodeWideStringPointer(NdrBuffer buf) throws NdrException {
        int pointer = buf.dec_ndr_long();
        if (pointer == 0) {
            return null; // NULL pointer
        }

        int maxCount = buf.dec_ndr_long();
        int offset = buf.dec_ndr_long();
        int actualCount = buf.dec_ndr_long();

        if (actualCount <= 0) {
            return "";
        }

        // Read wide string data (UTF-16LE)
        int byteCount = (actualCount - 1) * 2; // Exclude null terminator
        byte[] wideBytes = new byte[byteCount];
        buf.readOctetArray(wideBytes, 0, byteCount);

        // Skip null terminator
        buf.dec_ndr_short();

        // Skip padding
        int padding = (4 - ((byteCount + 2) % 4)) % 4;
        for (int i = 0; i < padding; i++) {
            buf.dec_ndr_small();
        }

        return new String(wideBytes, StandardCharsets.UTF_16LE);
    }
}