/* org.codelibs.jcifs.smb smb client library in Java
 * Copyright (C) 2007  "Michael B. Allen" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb.internal.smb1.net;

import java.util.Objects;

import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.impl.FileEntry;
import org.codelibs.jcifs.smb.util.Hexdump;

/**
 * Internal use only
 *
 *
 * <p>This class is intended for internal use.</p>
 */
public class SmbShareInfo implements FileEntry {

    /**
     * The network name of the share.
     */
    protected String netName;
    /**
     * The type of the share (e.g., disk, printer, IPC).
     */
    protected int type;
    /**
     * The optional comment or description for the share.
     */
    protected String remark;

    /**
     * Default constructor for SmbShareInfo.
     */
    public SmbShareInfo() {
    }

    /**
     * Constructs an SmbShareInfo with the specified properties.
     *
     * @param netName the network name of the share
     * @param type the type of the share
     * @param remark the optional comment or description for the share
     */
    public SmbShareInfo(final String netName, final int type, final String remark) {
        this.netName = netName;
        this.type = type;
        this.remark = remark;
    }

    @Override
    public String getName() {
        return this.netName;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.impl.FileEntry#getFileIndex()
     */
    @Override
    public int getFileIndex() {
        return 0;
    }

    @Override
    public int getType() {
        /*
         * 0x80000000 means hidden but SmbFile.isHidden() checks for $ at end
         */
        switch (this.type & 0xFFFF) {
        case 1:
            return SmbConstants.TYPE_PRINTER;
        case 3:
            return SmbConstants.TYPE_NAMED_PIPE;
        }
        return SmbConstants.TYPE_SHARE;
    }

    @Override
    public int getAttributes() {
        return SmbConstants.ATTR_READONLY | SmbConstants.ATTR_DIRECTORY;
    }

    @Override
    public long createTime() {
        return 0L;
    }

    @Override
    public long lastModified() {
        return 0L;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.impl.FileEntry#lastAccess()
     */
    @Override
    public long lastAccess() {
        return 0L;
    }

    @Override
    public long length() {
        return 0L;
    }

    @Override
    public boolean equals(final Object obj) {
        if (obj instanceof final SmbShareInfo si) {
            return Objects.equals(this.netName, si.netName);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(this.netName);
    }

    @Override
    public String toString() {
        return ("SmbShareInfo[" + "netName=" + this.netName + ",type=0x" + Hexdump.toHexString(this.type, 8) + ",remark=" + this.remark
                + "]");
    }
}
