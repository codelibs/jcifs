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

import java.io.IOException;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.DfsReferralData;
import org.codelibs.jcifs.smb.SmbSession;
import org.codelibs.jcifs.smb.SmbTransport;

/**
 * Internal interface for SMB transport operations.
 *
 * This interface provides internal methods for managing
 * SMB network transport and communication.
 *
 * @author mbechler
 */
public interface SmbTransportInternal extends SmbTransport {

    /**
     * Checks if the transport supports the specified capability.
     *
     * @param cap the capability flag to check
     * @return whether the transport has the given capability
     * @throws SmbException if an error occurs checking capabilities
     */
    boolean hasCapability(int cap) throws SmbException;

    /**
     * Checks if the transport has been disconnected.
     *
     * @return whether the transport has been disconnected
     */
    boolean isDisconnected();

    /**
     * Disconnects the transport from the remote server.
     *
     * @param hard if true, force immediate disconnection
     * @param inuse whether the connection is currently in use
     * @return whether the connection was in use
     * @throws IOException if an I/O error occurs during disconnection
     */
    boolean disconnect(boolean hard, boolean inuse) throws IOException;

    /**
     * Ensures the transport is connected to the remote server.
     *
     * @return whether the transport was connected
     * @throws SmbException if an SMB error occurs
     * @throws IOException if an I/O error occurs
     */
    boolean ensureConnected() throws IOException;

    /**
     * Gets DFS referrals for the specified path.
     *
     * @param ctx the CIFS context
     * @param name the DFS path to resolve
     * @param targetHost the target host name
     * @param targetDomain the target domain
     * @param rn the referral number
     * @return dfs referral
     * @throws SmbException if an SMB error occurs
     * @throws CIFSException if a CIFS error occurs
     */
    DfsReferralData getDfsReferrals(CIFSContext ctx, String name, String targetHost, String targetDomain, int rn) throws CIFSException;

    /**
     * Checks if message signing is supported but not mandatory.
     *
     * @return whether signatures are supported but not required
     * @throws SmbException if an error occurs checking signing status
     */
    boolean isSigningOptional() throws SmbException;

    /**
     * Checks if message signing is mandatory for this connection.
     *
     * @return whether signatures are enforced from either side
     * @throws SmbException if an error occurs checking signing status
     */
    boolean isSigningEnforced() throws SmbException;

    /**
     * Gets the server's encryption key for authentication.
     *
     * @return the encryption key used by the server
     */
    byte[] getServerEncryptionKey();

    /**
     * Gets or creates an SMB session for the given context.
     *
     * @param ctx the CIFS context
     * @return session
     */
    SmbSession getSmbSession(CIFSContext ctx);

    /**
     * Gets or creates an SMB session for the specified target.
     *
     * @param tf the CIFS context
     * @param targetHost the target host name
     * @param targetDomain the target domain
     * @return session
     */
    SmbSession getSmbSession(CIFSContext tf, String targetHost, String targetDomain);

    /**
     * Checks if this transport uses the SMB2 protocol.
     *
     * @return whether this is a SMB2 connection
     * @throws SmbException if an error occurs checking protocol version
     */
    boolean isSMB2() throws SmbException;

    /**
     * Gets the number of currently pending requests.
     *
     * @return number of inflight requests
     */
    int getInflightRequests();
}
