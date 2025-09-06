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
package org.codelibs.jcifs.smb.internal.smb2.rdma;

/**
 * RDMA capability flags indicating what operations are supported
 * by an RDMA provider implementation.
 */
public enum RdmaCapability {
    /**
     * Remote direct read operations
     */
    RDMA_READ,

    /**
     * Remote direct write operations
     */
    RDMA_WRITE,

    /**
     * Traditional send/receive with RDMA
     */
    RDMA_SEND_RECEIVE,

    /**
     * Dynamic memory registration
     */
    MEMORY_REGISTRATION,

    /**
     * Fast memory region registration
     */
    FAST_REGISTRATION
}
