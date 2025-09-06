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
package org.codelibs.jcifs.smb.internal.smb2.lease;

/**
 * Defines the scope of directory caching for SMB3 directory leasing
 */
public enum DirectoryCacheScope {
    /**
     * Cache only direct children of the directory
     */
    IMMEDIATE_CHILDREN,

    /**
     * Cache entire subtree recursively (if supported by server)
     */
    RECURSIVE_TREE,

    /**
     * Cache only file attributes but not content
     */
    METADATA_ONLY,

    /**
     * Cache complete directory listing including all metadata
     */
    FULL_ENUMERATION
}