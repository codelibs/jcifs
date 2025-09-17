/* org.codelibs.jcifs.smb msrpc client library in Java
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

package org.codelibs.jcifs.smb.dcerpc;

/**
 * Constants for DCERPC protocol operations.
 * This interface defines the constants used in DCERPC communication including
 * packet types, flags, and UUID identifiers.
 */
public interface DcerpcConstants {

    /**
     * NDR syntax UUID for DCE/RPC protocol
     */
    UUID DCERPC_UUID_SYNTAX_NDR = new UUID("8a885d04-1ceb-11c9-9fe8-08002b104860");

    /**
     * First fragment flag - indicates first fragment of a multi-fragment message
     */
    int DCERPC_FIRST_FRAG = 0x01; /* First fragment */
    /**
     * Last fragment flag - indicates last fragment of a multi-fragment message
     */
    int DCERPC_LAST_FRAG = 0x02; /* Last fragment */
    /**
     * Pending cancel flag - indicates cancel was pending at sender
     */
    int DCERPC_PENDING_CANCEL = 0x04; /* Cancel was pending at sender */
    /**
     * Reserved flag for future use
     */
    int DCERPC_RESERVED_1 = 0x08;
    /**
     * Supports concurrent multiplexing flag.
     */
    int DCERPC_CONC_MPX = 0x10; /* supports concurrent multiplexing */
    /**
     * Did not execute flag - indicates request was not executed
     */
    int DCERPC_DID_NOT_EXECUTE = 0x20;
    /**
     * Maybe flag - indicates 'maybe' call semantics requested
     */
    int DCERPC_MAYBE = 0x40; /* `maybe' call semantics requested */
    /**
     * Object UUID flag - if true, a non-nil object UUID is present
     */
    int DCERPC_OBJECT_UUID = 0x80; /* if true, a non-nil object UUID */

    // Packet Types (ptype)
    /**
     * Request packet type
     */
    int RPC_PT_REQUEST = 0x00;
    /**
     * Ping packet type
     */
    int RPC_PT_PING = 0x01;
    /**
     * Response packet type
     */
    int RPC_PT_RESPONSE = 0x02;
    /**
     * Fault packet type - indicates an error
     */
    int RPC_PT_FAULT = 0x03;
    /**
     * Bind packet type - establishes context
     */
    int RPC_PT_BIND = 0x0B;
    /**
     * Bind acknowledgment packet type
     */
    int RPC_PT_BIND_ACK = 0x0C;
    /**
     * Bind negative acknowledgment packet type
     */
    int RPC_PT_BIND_NAK = 0x0D;
    /**
     * Alter context packet type
     */
    int RPC_PT_ALTER_CONTEXT = 0x0E;
    /**
     * Alter context response packet type
     */
    int RPC_PT_ALTER_CONTEXT_RESPONSE = 0x0F;
    /**
     * Shutdown packet type
     */
    int RPC_PT_SHUTDOWN = 0x11;
    /**
     * Cancel packet type
     */
    int RPC_PT_CANCEL = 0x12;
    /**
     * Acknowledgment packet type
     */
    int RPC_PT_ACK = 0x13;
    /**
     * Reject packet type
     */
    int RPC_PT_REJECT = 0x14;
    /**
     * Connection-oriented cancel packet type
     */
    int RPC_PT_CO_CANCEL = 0x15;
    /**
     * Orphaned packet type
     */
    int RPC_PT_ORPHANED = 0x16;

    // RPC_C_PF_ flags (packet flags)
    /**
     * Broadcast packet flag
     */
    int RPC_C_PF_BROADCAST = 0x01;
    /**
     * No fragmentation packet flag
     */
    int RPC_C_PF_NO_FRAGMENT = 0x02;
    /**
     * Maybe semantics packet flag
     */
    int RPC_C_PF_MAYBE = 0x04;
    /**
     * Idempotent operation packet flag
     */
    int RPC_C_PF_IDEMPOTENT = 0x08;
    /**
     * Broadcast with maybe semantics packet flag
     */
    int RPC_C_PF_BROADCAST_MAYBE = 0x10;
    /**
     * Not idempotent operation packet flag
     */
    int RPC_C_PF_NOT_IDEMPOTENT = 0x20;
    /**
     * No automatic listening packet flag
     */
    int RPC_C_PF_NO_AUTO_LISTEN = 0x40;
    /**
     * No automatic retry packet flag
     */
    int RPC_C_PF_NO_AUTO_RETRY = 0x80;
}
