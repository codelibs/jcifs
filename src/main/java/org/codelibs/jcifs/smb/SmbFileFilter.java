/*
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
 * Filter interface for SMB file filtering.
 *
 * This interface allows selective filtering of files
 * when listing directory contents in SMB shares.
 */
public interface SmbFileFilter {

    /**
     * Tests whether the specified SMB file should be included in a file list.
     *
     * @param file the SMB file to test for inclusion
     * @return whether the given file should be included
     * @throws SmbException if an error occurs while accessing the file
     */
    boolean accept(SmbFile file) throws SmbException;
}
