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


@SuppressWarnings ( "javadoc" )
public interface DcerpcConstants {

    public static final UUID DCERPC_UUID_SYNTAX_NDR = new UUID("8a885d04-1ceb-11c9-9fe8-08002b104860");

    public static final int DCERPC_FIRST_FRAG = 0x01; /* First fragment */
    public static final int DCERPC_LAST_FRAG = 0x02; /* Last fragment */
    public static final int DCERPC_PENDING_CANCEL = 0x04; /* Cancel was pending at sender */
    public static final int DCERPC_RESERVED_1 = 0x08;
    public static final int DCERPC_CONC_MPX = 0x10; /* supports concurrent multiplexing */
    public static final int DCERPC_DID_NOT_EXECUTE = 0x20;
    public static final int DCERPC_MAYBE = 0x40; /* `maybe' call semantics requested */
    public static final int DCERPC_OBJECT_UUID = 0x80; /* if true, a non-nil object UUID */

    // Packet Types (ptype)
    public static final int RPC_PT_REQUEST = 0x00;
    public static final int RPC_PT_PING = 0x01;
    public static final int RPC_PT_RESPONSE = 0x02;
    public static final int RPC_PT_FAULT = 0x03;
    public static final int RPC_PT_BIND = 0x0B;
    public static final int RPC_PT_BIND_ACK = 0x0C;
    public static final int RPC_PT_BIND_NAK = 0x0D;
    public static final int RPC_PT_ALTER_CONTEXT = 0x0E;
    public static final int RPC_PT_ALTER_CONTEXT_RESPONSE = 0x0F;
    public static final int RPC_PT_SHUTDOWN = 0x11;
    public static final int RPC_PT_CANCEL = 0x12;
    public static final int RPC_PT_ACK = 0x13;
    public static final int RPC_PT_REJECT = 0x14;
    public static final int RPC_PT_CO_CANCEL = 0x15;
    public static final int RPC_PT_ORPHANED = 0x16;

    // RPC_C_PF_ flags (packet flags)
    public static final int RPC_C_PF_BROADCAST = 0x01;
    public static final int RPC_C_PF_NO_FRAGMENT = 0x02;
    public static final int RPC_C_PF_MAYBE = 0x04;
    public static final int RPC_C_PF_IDEMPOTENT = 0x08;
    public static final int RPC_C_PF_BROADCAST_MAYBE = 0x10;
    public static final int RPC_C_PF_NOT_IDEMPOTENT = 0x20;
    public static final int RPC_C_PF_NO_AUTO_LISTEN = 0x40;
    public static final int RPC_C_PF_NO_AUTO_RETRY = 0x80;
}
