/* jcifs smb client library in Java
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

package jcifs.smb;

@SuppressWarnings("javadoc")
public interface WinError {

    /*
     * Don't bother to edit this. Everything within the interface
     * block is automatically generated from the ntstatus package.
     */

    int ERROR_SUCCESS = 0;
    int ERROR_ACCESS_DENIED = 5;
    int ERROR_REQ_NOT_ACCEP = 71;
    int ERROR_BAD_PIPE = 230;
    int ERROR_PIPE_BUSY = 231;
    int ERROR_NO_DATA = 232;
    int ERROR_PIPE_NOT_CONNECTED = 233;
    int ERROR_MORE_DATA = 234;
    int ERROR_SERVICE_NOT_INSTALLED = 2184;
    int ERROR_NO_BROWSER_SERVERS_FOUND = 6118;

    int[] WINERR_CODES = { ERROR_SUCCESS, ERROR_ACCESS_DENIED, ERROR_REQ_NOT_ACCEP, ERROR_BAD_PIPE, ERROR_PIPE_BUSY, ERROR_NO_DATA,
            ERROR_PIPE_NOT_CONNECTED, ERROR_MORE_DATA, ERROR_SERVICE_NOT_INSTALLED, ERROR_NO_BROWSER_SERVERS_FOUND, };

    String[] WINERR_MESSAGES = { "The operation completed successfully.", "Access is denied.",
            "No more connections can be made to this remote computer at this time because there are already as many connections as the computer can accept.",
            "The pipe state is invalid.", "All pipe instances are busy.", "The pipe is being closed.",
            "No process is on the other end of the pipe.", "More data is available.", "The service is not available",
            "The list of servers for this workgroup is not currently available.", };
}
