/* org.codelibs.jcifs.smb smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb.internal;

/**
 * Interface for basic SMB file information.
 * Provides access to fundamental file metadata including attributes, timestamps,
 * and file size information retrieved from SMB file system operations.
 *
 * @author mbechler
 */
public interface SmbBasicFileInfo {

    /**
     * Gets the file attributes.
     *
     * @return file attributes
     */
    int getAttributes();

    /**
     * Gets the file creation time.
     *
     * @return file create time
     */
    long getCreateTime();

    /**
     * Gets the file last write time.
     *
     * @return file last write time
     */
    long getLastWriteTime();

    /**
     * Gets the file last access time.
     *
     * @return file last access time
     */
    long getLastAccessTime();

    /**
     * Gets the file size in bytes.
     *
     * @return file size
     */
    long getSize();
}
