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

/**
 * Represents a witness unregistration response as defined in MS-SWN specification.
 * Contains the result of a witness unregistration request.
 */
public class WitnessUnregisterResponse {
    /**
     * Creates a new witness unregister response.
     */
    public WitnessUnregisterResponse() {
        // Default constructor
    }

    private int returnCode;
    private String error;

    /**
     * Checks if the unregistration was successful.
     *
     * @return true if successful
     */
    public boolean isSuccess() {
        return returnCode == 0;
    }

    /**
     * Gets a human-readable error description.
     *
     * @return the error description
     */
    public String getError() {
        return error != null ? error : "Error code: " + returnCode;
    }

    /**
     * Sets the error message.
     *
     * @param error the error message
     */
    public void setError(String error) {
        this.error = error;
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