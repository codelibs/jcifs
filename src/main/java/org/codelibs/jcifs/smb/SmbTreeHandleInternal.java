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
package org.codelibs.jcifs.smb;

/**
 * Internal interface for SMB tree handle operations.
 *
 * This interface provides internal methods for managing
 * SMB tree connections and their lifecycle.
 *
 * @author mbechler
 */
public interface SmbTreeHandleInternal extends SmbTreeHandle {

    /**
     * Releases this tree handle back to the pool for reuse
     */
    void release();

    /**
     * Ensures that DFS referrals have been resolved for this tree
     * @throws SmbSystemException if an SMB-specific error occurs
     * @throws CIFSException if a general CIFS error occurs
     */
    void ensureDFSResolved() throws CIFSException;

    /**
     * Checks if the server has the specified capability
     * @param cap the capability flag to check
     * @return whether the capability is present
     * @throws CIFSException if an error occurs checking capabilities
     */
    boolean hasCapability(int cap) throws CIFSException;

    /**
     * Gets the send buffer size of the underlying SMB connection
     * @return the send buffer size of the underlying connection
     * @throws CIFSException if an error occurs retrieving the buffer size
     */
    int getSendBufferSize() throws CIFSException;

    /**
     * Gets the receive buffer size of the underlying SMB connection
     * @return the receive buffer size of the underlying connection
     * @throws CIFSException if an error occurs retrieving the buffer size
     */
    int getReceiveBufferSize() throws CIFSException;

    /**
     * Gets the maximum buffer size supported by the server
     * @return the maximum buffer size reported by the server
     * @throws CIFSException if an error occurs retrieving the buffer size
     */
    int getMaximumBufferSize() throws CIFSException;

    /**
     * Checks if SMB message signing is active for this session
     * @return whether the session uses SMB signing
     * @throws CIFSException if a general CIFS error occurs
     * @throws SmbSystemException if an SMB-specific error occurs
     */
    boolean areSignaturesActive() throws CIFSException;

    /**
     * Internal/testing use only
     *
     * @return attached session
     */
    SmbSession getSession();
}
