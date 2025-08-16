/*
 * © 2016 AgNO3 Gmbh & Co. KG
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
package jcifs.smb;

import javax.security.auth.Subject;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Credentials;

/**
 * Internal interface for SMB credentials.
 *
 * This interface provides internal methods for managing
 * and accessing SMB authentication credentials.
 *
 * @author mbechler
 */
public interface CredentialsInternal extends Cloneable, Credentials {

    /**
     * Create a copy of the credentials.
     * @return a copy of the credentials
     */
    CredentialsInternal clone();

    /**
     * Create an SSP context for authentication.
     * @param tc the CIFS context
     * @param targetDomain the target domain for authentication
     * @param host the target host
     * @param initialToken initial authentication token, if any
     * @param doSigning whether message signing should be enabled
     * @return a new SSP authentication context
     * @throws SmbException if context creation fails
     */
    SSPContext createContext(CIFSContext tc, String targetDomain, String host, byte[] initialToken, boolean doSigning) throws SmbException;

    /**
     * Get the security subject associated with these credentials.
     * @return subject associated with the credentials
     */
    Subject getSubject();

    /**
     * Refresh the credentials.
     * @throws CIFSException if refresh fails
     */
    void refresh() throws CIFSException;
}
