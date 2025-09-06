/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
package org.codelibs.jcifs.smb.internal;

/**
 * Interface for SMB Tree Connect response messages.
 * Handles the server's response to a tree connect request, providing tree ID,
 * service type, and DFS information for the connected share.
 *
 * @author mbechler
 */
public interface TreeConnectResponse extends CommonServerMessageBlockResponse {

    /**
     * Returns the tree identifier (TID) assigned to this tree connection.
     *
     * @return tree id
     */
    int getTid();

    /**
     * Returns the service type of the connected share (e.g., A: for disk, LPT1: for printer, IPC for named pipe).
     *
     * @return service
     */
    String getService();

    /**
     * Indicates whether the connected share is part of a Distributed File System (DFS) namespace.
     *
     * @return whether the share is in DFS
     */
    boolean isShareDfs();

    /**
     * Indicates whether the tree connection has been successfully established and has a valid tree ID.
     *
     * @return whether the tree id is a valid one
     */
    boolean isValidTid();

}
