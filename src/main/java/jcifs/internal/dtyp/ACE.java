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
package jcifs.internal.dtyp;

import jcifs.Decodable;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.SID;
import jcifs.util.Hexdump;

/**
 * An Access Control Entry (ACE) is an element in a security descriptor
 * such as those associated with files and directories. The Windows OS
 * determines which users have the necessary permissions to access objects
 * based on these entries.
 * <p>
 * To fully understand the information exposed by this class a description
 * of the access check algorithm used by Windows is required. The following
 * is a basic description of the algorithm. For a more complete description
 * we recommend reading the section on Access Control in Keith Brown's
 * "The .NET Developer's Guide to Windows Security" (which is also
 * available online).
 * <p>
 * Direct ACEs are evaluated first in order. The SID of the user performing
 * the operation and the desired access bits are compared to the SID
 * and access mask of each ACE. If the SID matches, the allow/deny flags
 * and access mask are considered. If the ACE is a "deny"
 * ACE and <i>any</i> of the desired access bits match bits in the access
 * mask of the ACE, the whole access check fails. If the ACE is an "allow"
 * ACE and <i>all</i> of the bits in the desired access bits match bits in
 * the access mask of the ACE, the access check is successful. Otherwise,
 * more ACEs are evaluated until all desired access bits (combined)
 * are "allowed". If all of the desired access bits are not "allowed"
 * the then same process is repeated for inherited ACEs.
 * <p>
 * For example, if user <code>WNET\alice</code> tries to open a file
 * with desired access bits <code>0x00000003</code> (<code>FILE_READ_DATA |
 * FILE_WRITE_DATA</code>) and the target file has the following security
 * descriptor ACEs:
 *
 * <pre>
 * Allow WNET\alice     0x001200A9  Direct
 * Allow Administrators 0x001F01FF  Inherited
 * Allow SYSTEM         0x001F01FF  Inherited
 * </pre>
 *
 * the access check would fail because the direct ACE has an access mask
 * of <code>0x001200A9</code> which doesn't have the
 * <code>FILE_WRITE_DATA</code> bit on (bit <code>0x00000002</code>). Actually, this isn't quite correct. If
 * <code>WNET\alice</code> is in the local <code>Administrators</code> group the access check
 * will succeed because the inherited ACE allows local <code>Administrators</code>
 * both <code>FILE_READ_DATA</code> and <code>FILE_WRITE_DATA</code> access.
 *
 */
public class ACE implements jcifs.ACE, Decodable {

    /**
     * Default constructor for ACE
     */
    public ACE() {
        // Default constructor
    }

    boolean allow;
    int flags;
    int access;
    SID sid;

    @Override
    public boolean isAllow() {
        return this.allow;
    }

    @Override
    public boolean isInherited() {
        return (this.flags & FLAGS_INHERITED) != 0;
    }

    @Override
    public int getFlags() {
        return this.flags;
    }

    @Override
    public String getApplyToText() {
        switch (this.flags & (FLAGS_OBJECT_INHERIT | FLAGS_CONTAINER_INHERIT | FLAGS_INHERIT_ONLY)) {
        case 0x00:
            return "This folder only";
        case 0x03:
            return "This folder, subfolders and files";
        case 0x0B:
            return "Subfolders and files only";
        case 0x02:
            return "This folder and subfolders";
        case 0x0A:
            return "Subfolders only";
        case 0x01:
            return "This folder and files";
        case 0x09:
            return "Files only";
        }
        return "Invalid";
    }

    @Override
    public int getAccessMask() {
        return this.access;
    }

    @Override
    public SID getSID() {
        return this.sid;
    }

    @Override
    public int decode(final byte[] buf, int bi, final int len) {
        this.allow = buf[bi] == (byte) 0x00;
        bi++;
        this.flags = buf[bi++] & 0xFF;
        final int size = SMBUtil.readInt2(buf, bi);
        bi += 2;
        this.access = SMBUtil.readInt4(buf, bi);
        bi += 4;
        this.sid = new SID(buf, bi);
        return size;
    }

    void appendCol(final StringBuffer sb, final String str, final int width) {
        sb.append(str);
        final int count = width - str.length();
        for (int i = 0; i < count; i++) {
            sb.append(' ');
        }
    }

    /**
     * Return a string represeting this ACE.
     * <p>
     * Note: This function should probably be changed to return SDDL
     * fragments but currently it does not.
     */
    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer();
        sb.append(isAllow() ? "Allow " : "Deny  ");
        appendCol(sb, this.sid.toDisplayString(), 25);
        sb.append(" 0x").append(Hexdump.toHexString(this.access, 8)).append(' ');
        sb.append(isInherited() ? "Inherited " : "Direct    ");
        appendCol(sb, getApplyToText(), 34);
        return sb.toString();
    }
}
