/*
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
package org.codelibs.jcifs.smb.pac;

import org.codelibs.jcifs.smb.impl.SID;

/**
 * Represents a Security Identifier (SID) with associated attributes within a PAC structure.
 * This class encapsulates a SID and its attribute flags as used in Kerberos PAC data.
 */
public class PacSidAttributes {

    private final SID id;
    private final int attributes;

    /**
     * Constructs a new PacSidAttributes instance.
     *
     * @param id the Security Identifier
     * @param attributes the attribute flags associated with the SID
     */
    public PacSidAttributes(final SID id, final int attributes) {
        this.id = id;
        this.attributes = attributes;
    }

    /**
     * Gets the Security Identifier.
     *
     * @return the SID associated with this instance
     */
    public SID getId() {
        return this.id;
    }

    /**
     * Gets the attribute flags associated with the SID.
     *
     * @return the attribute flags
     */
    public int getAttributes() {
        return this.attributes;
    }

}
