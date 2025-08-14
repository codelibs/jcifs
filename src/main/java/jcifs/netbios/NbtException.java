/* jcifs smb client library in Java
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

package jcifs.netbios;

import jcifs.CIFSException;

/**
 * NetBIOS exception class for NBT-related errors.
 *
 * This exception encapsulates NetBIOS name service and session service errors
 * with specific error classes and codes.
 */
public class NbtException extends CIFSException {

    /**
     *
     */
    private static final long serialVersionUID = 492638554095148960L;
    // error classes
    /** Success status code */
    public static final int SUCCESS = 0;
    /** Name service error class */
    public static final int ERR_NAM_SRVC = 0x01;
    /** Session service error class */
    public static final int ERR_SSN_SRVC = 0x02;

    // name service error codes
    /** Format error in the name service */
    public static final int FMT_ERR = 0x1;
    /** Server error in the name service */
    public static final int SRV_ERR = 0x2;
    /** Implementation error in the name service */
    public static final int IMP_ERR = 0x4;
    /** Refused error in the name service */
    public static final int RFS_ERR = 0x5;
    /** Active error in the name service */
    public static final int ACT_ERR = 0x6;
    /** Name in conflict error */
    public static final int CFT_ERR = 0x7;

    // session service error codes
    /** Connection refused by the remote host */
    public static final int CONNECTION_REFUSED = -1;
    /** Not listening on the called name */
    public static final int NOT_LISTENING_CALLED = 0x80;
    /** Not listening for the calling name */
    public static final int NOT_LISTENING_CALLING = 0x81;
    /** Called name not present */
    public static final int CALLED_NOT_PRESENT = 0x82;
    /** Insufficient resources to establish session */
    public static final int NO_RESOURCES = 0x83;
    /** Unspecified session service error */
    public static final int UNSPECIFIED = 0x8F;

    /** The NetBIOS error class */
    public int errorClass;
    /** The NetBIOS error code */
    public int errorCode;

    /**
     * Converts NetBIOS error class and code to a human-readable string.
     *
     * @param errorClass the error class
     * @param errorCode the error code
     * @return a descriptive error string
     */
    public static String getErrorString(final int errorClass, final int errorCode) {
        StringBuilder result = new StringBuilder();
        switch (errorClass) {
        case SUCCESS:
            result.append("SUCCESS");
            break;
        case ERR_NAM_SRVC:
            result.append("ERR_NAM_SRVC/");
            switch (errorCode) {
            case FMT_ERR:
                result.append("FMT_ERR: Format Error");
            default:
                result.append("Unknown error code: ").append(errorCode);
            }
            break;
        case ERR_SSN_SRVC:
            result.append("ERR_SSN_SRVC/");
            switch (errorCode) {
            case CONNECTION_REFUSED:
                result.append("Connection refused");
                break;
            case NOT_LISTENING_CALLED:
                result.append("Not listening on called name");
                break;
            case NOT_LISTENING_CALLING:
                result.append("Not listening for calling name");
                break;
            case CALLED_NOT_PRESENT:
                result.append("Called name not present");
                break;
            case NO_RESOURCES:
                result.append("Called name present, but insufficient resources");
                break;
            case UNSPECIFIED:
                result.append("Unspecified error");
                break;
            default:
                result.append("Unknown error code: ").append(errorCode);
            }
            break;
        default:
            result.append("unknown error class: ").append(errorClass);
        }
        return result.toString();
    }

    /**
     * Constructs an NbtException with the specified error class and code.
     *
     * @param errorClass the NetBIOS error class
     * @param errorCode the NetBIOS error code
     */
    public NbtException(final int errorClass, final int errorCode) {
        super(getErrorString(errorClass, errorCode));
        this.errorClass = errorClass;
        this.errorCode = errorCode;
    }

    @Override
    public String toString() {
        return ("errorClass=" + this.errorClass + ",errorCode=" + this.errorCode + ",errorString="
                + getErrorString(this.errorClass, this.errorCode));
    }
}
