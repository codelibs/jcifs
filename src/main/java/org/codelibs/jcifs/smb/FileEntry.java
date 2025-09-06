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
package org.codelibs.jcifs.smb;

/**
 * Interface representing a file entry in an SMB directory listing.
 * Provides access to file metadata and attributes.
 *
 */
public interface FileEntry {

    /**
     * Gets the file name.
     *
     * @return the file name
     */
    String getName();

    /**
     * Gets the file type.
     *
     * @return the file type
     */
    int getType();

    /**
     * Gets the file attributes.
     *
     * @return the file attributes
     */
    int getAttributes();

    /**
     * Gets the file creation time.
     *
     * @return the creation time in milliseconds since epoch
     */
    long createTime();

    /**
     * Gets the last modified time.
     *
     * @return the last modified time in milliseconds since epoch
     */
    long lastModified();

    /**
     * Gets the last access time.
     *
     * @return the last access time in milliseconds since epoch
     */
    long lastAccess();

    /**
     * Gets the file size.
     *
     * @return the file size in bytes
     */
    long length();

    /**
     * Gets the file index.
     *
     * @return the file index inside the parent directory
     */
    int getFileIndex();
}
