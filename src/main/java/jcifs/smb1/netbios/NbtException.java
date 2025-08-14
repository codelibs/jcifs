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

package jcifs.smb1.netbios;

import java.io.IOException;

public class NbtException extends IOException {

    // error classes
    public static final int SUCCESS = 0;
    public static final int ERR_NAM_SRVC = 0x01;
    public static final int ERR_SSN_SRVC = 0x02;

    // name service error codes
    public static final int FMT_ERR = 0x1;
    public static final int SRV_ERR = 0x2;
    public static final int IMP_ERR = 0x4;
    public static final int RFS_ERR = 0x5;
    public static final int ACT_ERR = 0x6;
    public static final int CFT_ERR = 0x7;

    // session service error codes
    public static final int CONNECTION_REFUSED = -1;
    public static final int NOT_LISTENING_CALLED = 0x80;
    public static final int NOT_LISTENING_CALLING = 0x81;
    public static final int CALLED_NOT_PRESENT = 0x82;
    public static final int NO_RESOURCES = 0x83;
    public static final int UNSPECIFIED = 0x8F;

    public int errorClass;
    public int errorCode;

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

    public NbtException(final int errorClass, final int errorCode) {
        super(getErrorString(errorClass, errorCode));
        this.errorClass = errorClass;
        this.errorCode = errorCode;
    }

    @Override
    public String toString() {
        return ("errorClass=" + errorClass + ",errorCode=" + errorCode + ",errorString=" + getErrorString(errorClass, errorCode));
    }
}
