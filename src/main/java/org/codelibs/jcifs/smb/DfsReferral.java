/* org.codelibs.jcifs.smb smb client library in Java
 * Copyright (C) 2003  "Michael B. Allen" <jcifs at samba dot org>
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
 * Exception containing DFS referral information.
 * Thrown when a DFS referral is encountered during SMB operations.
 *
 * @author mbechler
 *
 *
 * <p>This class is intended for internal use.</p>
 */
public class DfsReferral extends SmbException {

    /**
     *
     */
    private static final long serialVersionUID = 1486630733410281686L;

    /** The underlying DFS referral data */
    private final DfsReferralData data;

    /**
     * Constructs a DfsReferral with the specified referral data
     *
     * @param data the DFS referral data
     */
    public DfsReferral(final DfsReferralData data) {
        this.data = data;
    }

    /**
     * Get the DFS referral data associated with this referral
     *
     * @return the DFS referral data
     */
    public DfsReferralData getData() {
        return this.data;
    }

    @Override
    public String toString() {
        return this.data.toString();
    }
}
