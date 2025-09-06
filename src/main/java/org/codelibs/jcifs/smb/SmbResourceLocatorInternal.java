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
 * Internal interface for SMB resource locators.
 *
 * This interface provides internal methods for locating
 * and resolving SMB resources.
 *
 * @author mbechler
 */
public interface SmbResourceLocatorInternal extends SmbResourceLocator {

    /**
     * Determines whether SMB signing should be enforced for connections to this resource.
     *
     * @return whether to enforce the use of signing on connection to this resource
     */
    boolean shouldForceSigning();

    /**
     * Determines whether this resource path overlaps with another resource path by sharing a common root.
     *
     * @param other the other resource locator to compare with
     * @return whether the paths share a common root
     * @throws CIFSException if an error occurs during comparison
     */
    boolean overlaps(SmbResourceLocator other) throws CIFSException;

    /**
     * Internal: for testing only
     *
     * @param dr the DFS referral data to process
     * @param reqPath the requested path to resolve
     * @return resolved unc path
     */
    String handleDFSReferral(DfsReferralData dr, String reqPath);
}
