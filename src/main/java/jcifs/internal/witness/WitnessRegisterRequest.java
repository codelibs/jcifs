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

/**
 * Represents a witness registration request as defined in MS-SWN specification.
 * Used to register for witness notifications from the witness service.
 */
public class WitnessRegisterRequest {
    /**
     * Creates a new witness register request.
     */
    public WitnessRegisterRequest() {
        // Default constructor
    }

    private int version;
    private String shareName;
    private String serverAddress;
    private int flags;

    /**
     * Gets the witness protocol version.
     *
     * @return the protocol version
     */
    public int getVersion() {
        return version;
    }

    /**
     * Sets the witness protocol version.
     *
     * @param version the protocol version
     */
    public void setVersion(int version) {
        this.version = version;
    }

    /**
     * Gets the share name to monitor.
     *
     * @return the share name
     */
    public String getShareName() {
        return shareName;
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
     * Gets the server address.
     *
     * @return the server address
     */
    public String getServerAddress() {
        return serverAddress;
    }

    /**
     * Sets the server address.
     *
     * @param serverAddress the server address
     */
    public void setServerAddress(String serverAddress) {
        this.serverAddress = serverAddress;
    }

    /**
     * Gets the registration flags.
     *
     * @return the flags
     */
    public int getFlags() {
        return flags;
    }

    /**
     * Sets the registration flags.
     *
     * @param flags the flags
     */
    public void setFlags(int flags) {
        this.flags = flags;
    }
}