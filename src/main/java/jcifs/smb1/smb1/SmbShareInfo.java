/* jcifs smb client library in Java
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

package jcifs.smb1.smb1;

import jcifs.smb1.util.Hexdump;

public class SmbShareInfo implements FileEntry {

    protected String netName;
    protected int type;
    protected String remark;

    public SmbShareInfo() {
    }

    public SmbShareInfo(final String netName, final int type, final String remark) {
        this.netName = netName;
        this.type = type;
        this.remark = remark;
    }

    @Override
    public String getName() {
        return netName;
    }

    @Override
    public int getType() {
        /* 0x80000000 means hidden but SmbFile.isHidden() checks for $ at end
         */
        switch (type & 0xFFFF) {
        case 1:
            return SmbFile.TYPE_PRINTER;
        case 3:
            return SmbFile.TYPE_NAMED_PIPE;
        }
        return SmbFile.TYPE_SHARE;
    }

    @Override
    public int getAttributes() {
        return SmbFile.ATTR_READONLY | SmbFile.ATTR_DIRECTORY;
    }

    @Override
    public long createTime() {
        return 0L;
    }

    @Override
    public long lastModified() {
        return 0L;
    }

    @Override
    public long length() {
        return 0L;
    }

    @Override
    public boolean equals(final Object obj) {
        if (obj instanceof final SmbShareInfo si) {
            return netName.equals(si.netName);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return netName.hashCode();
    }

    @Override
    public String toString() {
        return ("SmbShareInfo[" + "netName=" + netName + ",type=0x" + Hexdump.toHexString(type, 8) + ",remark=" + remark + "]");
    }
}
