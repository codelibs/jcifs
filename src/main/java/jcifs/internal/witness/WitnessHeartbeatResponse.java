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
 * Represents a witness heartbeat response as defined in MS-SWN specification.
 * Contains the result of a witness heartbeat request.
 */
public class WitnessHeartbeatResponse {
    private long sequenceNumber;
    private int returnCode;

    /**
     * Checks if the heartbeat was successful.
     *
     * @return true if successful
     */
    public boolean isSuccess() {
        return returnCode == 0;
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
     * Sets the sequence number.
     *
     * @param sequenceNumber the sequence number
     */
    public void setSequenceNumber(long sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    /**
     * Gets the return code.
     *
     * @return the return code
     */
    public int getReturnCode() {
        return returnCode;
    }

    /**
     * Sets the return code.
     *
     * @param returnCode the return code
     */
    public void setReturnCode(int returnCode) {
        this.returnCode = returnCode;
    }
}
