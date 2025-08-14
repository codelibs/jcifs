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
public interface DcerpcConstants {

    UUID DCERPC_UUID_SYNTAX_NDR = new UUID("8a885d04-1ceb-11c9-9fe8-08002b104860");

    int DCERPC_FIRST_FRAG = 0x01; /* First fragment */
    int DCERPC_LAST_FRAG = 0x02; /* Last fragment */
    int DCERPC_PENDING_CANCEL = 0x04; /* Cancel was pending at sender */
    int DCERPC_RESERVED_1 = 0x08;
    int DCERPC_CONC_MPX = 0x10; /* supports concurrent multiplexing */
    int DCERPC_DID_NOT_EXECUTE = 0x20;
    int DCERPC_MAYBE = 0x40; /* `maybe' call semantics requested */
    int DCERPC_OBJECT_UUID = 0x80; /* if true, a non-nil object UUID */

    // Packet Types (ptype)
    int RPC_PT_REQUEST = 0x00;
    int RPC_PT_PING = 0x01;
    int RPC_PT_RESPONSE = 0x02;
    int RPC_PT_FAULT = 0x03;
    int RPC_PT_BIND = 0x0B;
    int RPC_PT_BIND_ACK = 0x0C;
    int RPC_PT_BIND_NAK = 0x0D;
    int RPC_PT_ALTER_CONTEXT = 0x0E;
    int RPC_PT_ALTER_CONTEXT_RESPONSE = 0x0F;
    int RPC_PT_SHUTDOWN = 0x11;
    int RPC_PT_CANCEL = 0x12;
    int RPC_PT_ACK = 0x13;
    int RPC_PT_REJECT = 0x14;
    int RPC_PT_CO_CANCEL = 0x15;
    int RPC_PT_ORPHANED = 0x16;

    // RPC_C_PF_ flags (packet flags)
    int RPC_C_PF_BROADCAST = 0x01;
    int RPC_C_PF_NO_FRAGMENT = 0x02;
    int RPC_C_PF_MAYBE = 0x04;
    int RPC_C_PF_IDEMPOTENT = 0x08;
    int RPC_C_PF_BROADCAST_MAYBE = 0x10;
    int RPC_C_PF_NOT_IDEMPOTENT = 0x20;
    int RPC_C_PF_NO_AUTO_LISTEN = 0x40;
    int RPC_C_PF_NO_AUTO_RETRY = 0x80;
}
