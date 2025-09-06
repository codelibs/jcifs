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
 * Handle to a connected SMB tree
 *
 * @author mbechler
 *
 */
public interface SmbTreeHandle extends AutoCloseable {

    /**
     * Gets the active configuration for this tree handle
     * @return the active configuration
     */
    Configuration getConfig();

    /**
     * {@inheritDoc}
     *
     * @see java.lang.AutoCloseable#close()
     */
    @Override
    void close() throws CIFSException;

    /**
     * Checks whether the tree is currently connected
     * @return the tree is connected
     */
    boolean isConnected();

    /**
     * Gets the server timezone offset in milliseconds
     * @return server timezone offset
     * @throws CIFSException if an error occurs retrieving the timezone offset
     */
    long getServerTimeZoneOffset() throws CIFSException;

    /**
     * Gets the OEM domain name reported by the server
     * @return server reported domain name
     * @throws CIFSException if an error occurs retrieving the domain name
     */
    String getOEMDomainName() throws CIFSException;

    /**
     * Gets the name of the share this tree is connected to
     * @return the share we are connected to
     */
    String getConnectedShare();

    /**
     * Checks if this tree handle refers to the same tree as another
     * @param th the tree handle to compare with
     * @return whether the handles refer to the same tree
     */
    boolean isSameTree(SmbTreeHandle th);

    /**
     * Checks if this tree handle uses SMB2 or later protocol
     * @return whether this tree handle uses SMB2+
     */
    boolean isSMB2();

    /**
     * Gets the remote host name for this tree connection
     * @return the remote host name
     */
    String getRemoteHostName();

    /**
     * Gets the tree type (share type such as disk, printer, pipe, etc.)
     * @return the tree type
     */
    int getTreeType();

}