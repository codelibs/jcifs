/* org.codelibs.jcifs.smb smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.codelibs.jcifs.smb.util.Hexdump;

/**
 * There are hundreds of error codes that may be returned by a CIFS
 * server. Rather than represent each with it's own <code>Exception</code>
 * class, this class represents all of them. For many of the popular
 * error codes, constants and text messages like "The device is not ready"
 * are provided.
 * <p>
 * The jCIFS client maps DOS error codes to NTSTATUS codes. This means that
 * the user may receive a different error from a legacy server than that of
 * a newer variant such as Windows NT and above. If you should encounter
 * such a case, please report it to jcifs at samba dot org and we will
 * change the mapping.
 */

public class SmbException extends CIFSException implements NtStatus, DosError, WinError {

    /**
     *
     */
    private static final long serialVersionUID = 484863569441792249L;

    // to replace a bunch of one-off binary searches
    private static final Map<Integer, String> errorCodeMessages;
    private static final Map<Integer, String> winErrorCodeMessages;
    private static final Map<Integer, Integer> dosErrorCodeStatuses;

    static {
        final Map<Integer, String> errorCodeMessagesTmp = new HashMap<>();
        for (int i = 0; i < NT_STATUS_CODES.length; i++) {
            errorCodeMessagesTmp.put(NT_STATUS_CODES[i], NT_STATUS_MESSAGES[i]);
        }

        final Map<Integer, Integer> dosErrorCodeStatusesTmp = new HashMap<>();
        for (final int[] element : DOS_ERROR_CODES) {
            dosErrorCodeStatusesTmp.put(element[0], element[1]);
            final int mappedNtCode = element[1];
            final String mappedNtMessage = errorCodeMessagesTmp.get(mappedNtCode);
            if (mappedNtMessage != null) {
                errorCodeMessagesTmp.put(element[0], mappedNtMessage);
            }
        }

        // for backward compatibility since this is was different message in the NtStatus.NT_STATUS_CODES than returned
        // by getMessageByCode
        errorCodeMessagesTmp.put(0, "NT_STATUS_SUCCESS");

        errorCodeMessages = Collections.unmodifiableMap(errorCodeMessagesTmp);
        dosErrorCodeStatuses = Collections.unmodifiableMap(dosErrorCodeStatusesTmp);

        final Map<Integer, String> winErrorCodeMessagesTmp = new HashMap<>();
        for (int i = 0; i < WINERR_CODES.length; i++) {
            winErrorCodeMessagesTmp.put(WINERR_CODES[i], WINERR_MESSAGES[i]);
        }

        winErrorCodeMessages = Collections.unmodifiableMap(winErrorCodeMessagesTmp);

    }

    /**
     * Get the message string for an NT STATUS code
     *
     * @param errcode the NT STATUS error code
     * @return message for NT STATUS code
     */
    public static String getMessageByCode(final int errcode) {
        String message = errorCodeMessages.get(errcode);
        if (message == null) {
            message = "0x" + Hexdump.toHexString(errcode, 8);
        }
        return message;
    }

    static int getStatusByCode(final int errcode) {
        int statusCode;
        if ((errcode & 0xC0000000) != 0) {
            statusCode = errcode;
        } else if (dosErrorCodeStatuses.containsKey(errcode)) {
            statusCode = dosErrorCodeStatuses.get(errcode);
        } else {
            statusCode = NT_STATUS_UNSUCCESSFUL;
        }
        return statusCode;
    }

    static String getMessageByWinerrCode(final int errcode) {
        String message = winErrorCodeMessages.get(errcode);
        if (message == null) {
            message = "W" + Hexdump.toHexString(errcode, 8);
        }
        return message;
    }

    /** The SMB error status code */
    private int status;

    /**
     *
     /**
     * Constructs an SmbSystemException with no detail message
     */
    public SmbException() {
    }

    /**
     * Constructs an SmbSystemException with the specified error code and root cause
     *
     * @param errcode the SMB error code
     * @param rootCause the underlying cause of this exception
     */
    public SmbException(final int errcode, final Throwable rootCause) {
        super(getMessageByCode(errcode), rootCause);
        this.status = getStatusByCode(errcode);
    }

    /**
     * Constructs an SmbSystemException with the specified detail message
     *
     * @param msg the detail message
     */
    public SmbException(final String msg) {
        super(msg);
        this.status = NT_STATUS_UNSUCCESSFUL;
    }

    /**
     * Constructs an SmbSystemException with the specified detail message and root cause
     *
     * @param msg the detail message
     * @param rootCause the underlying cause of this exception
     */
    public SmbException(final String msg, final Throwable rootCause) {
        super(msg, rootCause);
        this.status = NT_STATUS_UNSUCCESSFUL;
    }

    /**
     * Constructs an SmbSystemException with the specified error code
     *
     * @param errcode the error code (either SMB or Windows error code)
     * @param winerr true if errcode is a Windows error code, false if it's an SMB error code
     */
    public SmbException(final int errcode, final boolean winerr) {
        super(winerr ? getMessageByWinerrCode(errcode) : getMessageByCode(errcode));
        this.status = winerr ? errcode : getStatusByCode(errcode);
    }

    /**
     * Get the NT STATUS code associated with this exception
     *
     * @return status code
     */
    public int getNtStatus() {
        return this.status;
    }

    /**
     * Get the root cause of this exception (deprecated - use getCause() instead)
     *
     * @return cause
     */
    @Deprecated
    public Throwable getRootCause() {
        return this.getCause();
    }

    /**
     * @param e
     * @return a CIFS exception wrapped in an SmbSystemException
     */
    static SmbException wrap(final CIFSException e) {
        if (e instanceof SmbException) {
            return (SmbException) e;
        }
        return new SmbException(e.getMessage(), e);
    }

}
