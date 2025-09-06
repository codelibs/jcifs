/*
 * © 2025 CodeLibs, Inc.
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
package org.codelibs.jcifs.smb.internal.witness;

/**
 * Enumeration of supported SMB Witness Protocol versions as defined in MS-SWN specification.
 * Each version corresponds to different Windows Server releases and capabilities.
 */
public enum WitnessVersion {
    /**
     * Witness Protocol Version 1 - Windows Server 2012
     */
    VERSION_1(0x00010001),

    /**
     * Witness Protocol Version 2 - Windows Server 2012 R2 and later
     */
    VERSION_2(0x00020000);

    private final int version;

    /**
     * Creates a new WitnessVersion with the specified version value.
     *
     * @param version the numeric version value
     */
    WitnessVersion(int version) {
        this.version = version;
    }

    /**
     * Gets the numeric version value.
     *
     * @return the version value
     */
    public int getValue() {
        return version;
    }

    /**
     * Gets the major version number.
     *
     * @return the major version
     */
    public int getMajorVersion() {
        return (version >> 16) & 0xFFFF;
    }

    /**
     * Gets the minor version number.
     *
     * @return the minor version
     */
    public int getMinorVersion() {
        return version & 0xFFFF;
    }
}
