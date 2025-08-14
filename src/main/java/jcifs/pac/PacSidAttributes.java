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
package jcifs.pac;

import jcifs.smb.SID;

public class PacSidAttributes {

    private final SID id;
    private final int attributes;

    public PacSidAttributes(final SID id, final int attributes) {
        this.id = id;
        this.attributes = attributes;
    }

    public SID getId() {
        return this.id;
    }

    public int getAttributes() {
        return this.attributes;
    }

}
