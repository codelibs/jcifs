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

import org.codelibs.jcifs.smb.SIDObject;

/**
 * Represents a group membership entry in PAC logon information.
 * Contains a group SIDObject and associated attributes.
 */
public class PacGroup {

    private final SIDObject id;
    private final int attributes;

    /**
     * Constructs a PAC group entry.
     * @param id the group's Security Identifier (SIDObject)
     * @param attributes the group membership attributes
     */
    public PacGroup(final SIDObject id, final int attributes) {
        this.id = id;
        this.attributes = attributes;
    }

    /**
     * Returns the group's Security Identifier.
     * @return the group SIDObject
     */
    public SIDObject getId() {
        return this.id;
    }

    /**
     * Returns the group membership attributes.
     * @return the attributes value
     */
    public int getAttributes() {
        return this.attributes;
    }

}
