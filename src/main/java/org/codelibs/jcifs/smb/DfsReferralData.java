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
 * Information returned in DFS referrals
 *
 * @author mbechler
 *
 * <p>This interface is intended for internal use.</p>
 */
public interface DfsReferralData {

    /**
     * Unwrap the referral data to a specific implementation type
     *
     * @param <T> the target type to unwrap to
     * @param type the class of the target type
     * @return the referral adapted to type
     * @throws ClassCastException
     *             if the type is not valid for this object
     */
    <T extends DfsReferralData> T unwrap(Class<T> type);

    /**
     * Get the server this referral points to
     *
     * @return the server this referral points to
     */
    String getServer();

    /**
     * Get the domain this referral is for
     *
     * @return the domain this referral is for
     */
    String getDomain();

    /**
     * Get the share this referral points to
     *
     * @return the share this referral points to
     */
    String getShare();

    /**
     * Get the number of characters from the UNC path that were consumed by this referral
     *
     * @return the number of characters from the unc path that were consumed by this referral
     */
    int getPathConsumed();

    /**
     * Get the replacement path for this referral
     *
     * @return the replacement path for this referal
     */
    String getPath();

    /**
     * Get the expiration time of this referral entry
     *
     * @return the expiration time of this entry
     */
    long getExpiration();

    /**
     * Get the next referral in the chain
     *
     * @return pointer to next referral, points to self if there is no further referral
     */
    DfsReferralData next();

    /**
     * Get the complete UNC path link for this referral
     *
     * @return the link
     */
    String getLink();

}
