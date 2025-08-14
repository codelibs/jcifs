/* jcifs msrpc client library in Java
 * Copyright (C) 2006  "Michael B. Allen" <jcifs at samba dot org>
 *                     "Eric Glass" <jcifs at samba dot org>
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

package jcifs.dcerpc;

@SuppressWarnings("javadoc")
public interface DcerpcError {

    int DCERPC_FAULT_OTHER = 0x00000001;
    int DCERPC_FAULT_ACCESS_DENIED = 0x00000005;
    int DCERPC_FAULT_CANT_PERFORM = 0x000006D8;
    int DCERPC_FAULT_NDR = 0x000006F7;
    int DCERPC_FAULT_INVALID_TAG = 0x1C000006;
    int DCERPC_FAULT_CONTEXT_MISMATCH = 0x1C00001A;
    int DCERPC_FAULT_OP_RNG_ERROR = 0x1C010002;
    int DCERPC_FAULT_UNK_IF = 0x1C010003;
    int DCERPC_FAULT_PROTO_ERROR = 0x1c01000b;

    int[] DCERPC_FAULT_CODES =
            { DCERPC_FAULT_OTHER, DCERPC_FAULT_ACCESS_DENIED, DCERPC_FAULT_CANT_PERFORM, DCERPC_FAULT_NDR, DCERPC_FAULT_INVALID_TAG,
                    DCERPC_FAULT_CONTEXT_MISMATCH, DCERPC_FAULT_OP_RNG_ERROR, DCERPC_FAULT_UNK_IF, DCERPC_FAULT_PROTO_ERROR };

    String[] DCERPC_FAULT_MESSAGES = { "DCERPC_FAULT_OTHER", "DCERPC_FAULT_ACCESS_DENIED", "DCERPC_FAULT_CANT_PERFORM", "DCERPC_FAULT_NDR",
            "DCERPC_FAULT_INVALID_TAG", "DCERPC_FAULT_CONTEXT_MISMATCH", "DCERPC_FAULT_OP_RNG_ERROR", "DCERPC_FAULT_UNK_IF",
            "DCERPC_FAULT_PROTO_ERROR" };
}
