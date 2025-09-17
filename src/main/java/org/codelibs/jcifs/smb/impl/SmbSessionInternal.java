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
package org.codelibs.jcifs.smb.impl;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.SmbSession;
import org.codelibs.jcifs.smb.SmbTransport;
import org.codelibs.jcifs.smb.SmbTree;

/**
 * Internal SMB session interface providing extended session management capabilities.
 * Defines methods for internal session operations and state management.
 *
 * @author mbechler
 *
 * <p>This interface is intended for internal use.</p>
 */
public interface SmbSessionInternal extends SmbSession {

    /**
     * Determines whether this session is currently in use.
     *
     * @return whether the session is in use
     */
    boolean isInUse();

    /**
     * Returns the current session key used for signing and encryption.
     *
     * @return the current session key
     * @throws CIFSException if the session key cannot be retrieved
     */
    byte[] getSessionKey() throws CIFSException;

    /**
     * Returns the SMB transport associated with this session.
     *
     * @return the transport for this session
     */
    SmbTransport getTransport();

    /**
     * Connect to the logon share
     *
     * @throws SmbException if the connection fails
     */
    void treeConnectLogon() throws SmbException;

    /**
     * Gets or creates an SMB tree connection for the specified share and service.
     *
     * @param share the share name to connect to
     * @param service the service type for the connection
     * @return tree instance
     */
    SmbTree getSmbTree(String share, String service);

    /**
     * Initiate reauthentication
     *
     * @throws CIFSException if reauthentication fails
     */
    void reauthenticate() throws CIFSException;
}
