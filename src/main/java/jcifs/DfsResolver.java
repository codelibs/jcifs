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
package jcifs;

/**
 * This is an internal API.
 *
 * @author mbechler
 *
 * <p>This interface is intended for internal use.</p>
 */
public interface DfsResolver {

    /**
     * Checks if a domain is trusted for DFS operations
     * @param tf the CIFS context
     * @param domain the domain name to check
     * @return whether the given domain is trusted
     * @throws CIFSException if the operation fails
     */
    boolean isTrustedDomain(CIFSContext tf, String domain) throws CIFSException;

    /**
     * Get a connection to the domain controller for a given domain
     *
     * @param tf the CIFS context
     * @param domain the domain name
     * @return connection to the domain controller
     * @throws CIFSException if the connection fails
     */
    SmbTransport getDc(CIFSContext tf, String domain) throws CIFSException;

    /**
     * Resolve the location of a DFS path
     *
     * @param domain the domain for the DFS referral
     * @param root the DFS root share
     * @param path the DFS path to resolve
     * @param tf the CIFS context containing configuration and credentials
     * @return the final referral for the given DFS path
     * @throws CIFSException if an error occurs during resolution
     * @throws jcifs.smb.SmbAuthException if authentication fails
     */
    DfsReferralData resolve(CIFSContext tf, String domain, String root, String path) throws CIFSException;

    /**
     * Add a referral to the cache
     *
     * @param path the DFS path for this referral
     * @param dr the DFS referral data to cache
     * @param tc the CIFS context containing configuration
     */
    void cache(CIFSContext tc, String path, DfsReferralData dr);

}