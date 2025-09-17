/* org.codelibs.jcifs.smb smb client library in Java
 * Copyright (C) 2004  "Michael B. Allen" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb1;

/**
 * Windows error codes used in SMB protocol operations.
 * These constants represent standard Windows error codes returned by SMB servers.
 */
public interface WinError {

    /* Don't bother to edit this. Everthing within the interface
     * block is automatically generated from the ntstatus package.
     */

    /** The operation completed successfully */
    int ERROR_SUCCESS = 0;
    /** Access is denied */
    int ERROR_ACCESS_DENIED = 5;
    /** No more connections can be made to this remote computer */
    int ERROR_REQ_NOT_ACCEP = 71;
    /** The pipe state is invalid */
    int ERROR_BAD_PIPE = 230;
    /** All pipe instances are busy */
    int ERROR_PIPE_BUSY = 231;
    /** The pipe is being closed */
    int ERROR_NO_DATA = 232;
    /** No process is on the other end of the pipe */
    int ERROR_PIPE_NOT_CONNECTED = 233;
    /** More data is available */
    int ERROR_MORE_DATA = 234;
    /** The list of servers for this workgroup is not currently available */
    int ERROR_NO_BROWSER_SERVERS_FOUND = 6118;

    /** Array of Windows error codes */
    int[] WINERR_CODES = { ERROR_SUCCESS, ERROR_ACCESS_DENIED, ERROR_REQ_NOT_ACCEP, ERROR_BAD_PIPE, ERROR_PIPE_BUSY, ERROR_NO_DATA,
            ERROR_PIPE_NOT_CONNECTED, ERROR_MORE_DATA, ERROR_NO_BROWSER_SERVERS_FOUND, };

    /** Array of Windows error messages corresponding to WINERR_CODES */
    String[] WINERR_MESSAGES = { "The operation completed successfully.", "Access is denied.",
            "No more connections can be made to this remote computer at this time because there are already as many connections as the computer can accept.",
            "The pipe state is invalid.", "All pipe instances are busy.", "The pipe is being closed.",
            "No process is on the other end of the pipe.", "More data is available.",
            "The list of servers for this workgroup is not currently available.", };
}
