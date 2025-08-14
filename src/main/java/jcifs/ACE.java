/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
package jcifs;

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
 */
public interface ACE {

    /**
     *
     */
    int FILE_READ_DATA = 0x00000001; // 1
    /**
     *
     */
    int FILE_WRITE_DATA = 0x00000002; // 2
    /**
     *
     */
    int FILE_APPEND_DATA = 0x00000004; // 3
    /**
     *
     */
    int FILE_READ_EA = 0x00000008; // 4
    /**
     *
     */
    int FILE_WRITE_EA = 0x00000010; // 5
    /**
     *
     */
    int FILE_EXECUTE = 0x00000020; // 6
    /**
     *
     */
    int FILE_DELETE = 0x00000040; // 7
    /**
     *
     */
    int FILE_READ_ATTRIBUTES = 0x00000080; // 8
    /**
     *
     */
    int FILE_WRITE_ATTRIBUTES = 0x00000100; // 9
    /**
     *
     */
    int DELETE = 0x00010000; // 16
    /**
     *
     */
    int READ_CONTROL = 0x00020000; // 17
    /**
     *
     */
    int WRITE_DAC = 0x00040000; // 18
    /**
     *
     */
    int WRITE_OWNER = 0x00080000; // 19
    /**
     *
     */
    int SYNCHRONIZE = 0x00100000; // 20
    /**
     *
     */
    int GENERIC_ALL = 0x10000000; // 28
    /**
     *
     */
    int GENERIC_EXECUTE = 0x20000000; // 29
    /**
     *
     */
    int GENERIC_WRITE = 0x40000000; // 30
    /**
     *
     */
    int GENERIC_READ = 0x80000000; // 31

    /**
     *
     */
    int FLAGS_OBJECT_INHERIT = 0x01;
    /**
     *
     */
    int FLAGS_CONTAINER_INHERIT = 0x02;
    /**
     *
     */
    int FLAGS_NO_PROPAGATE = 0x04;
    /**
     *
     */
    int FLAGS_INHERIT_ONLY = 0x08;
    /**
     *
     */
    int FLAGS_INHERITED = 0x10;

    /**
     * Return the SID associated with this ACE.
     *
     * @return ACE target SID
     */
    SID getSID();

    /**
     * Returns the access mask associated with this ACE. Use the
     * constants for <code>FILE_READ_DATA</code>, <code>FILE_WRITE_DATA</code>,
     * <code>READ_CONTROL</code>, <code>GENERIC_ALL</code>, etc with bitwise
     * operators to determine which bits of the mask are on or off.
     *
     * @return the access mask
     */
    int getAccessMask();

    /**
     * Returns the 'Apply To' text for inheritance of ACEs on
     * directories such as 'This folder, subfolder and files'. For
     * files the text is always 'This object only'.
     *
     * @return descriptive text for the ACE scope
     */
    String getApplyToText();

    /**
     * Returns the flags for this ACE. The <code>isInherited()</code>
     * method checks the <code>FLAGS_INHERITED</code> bit in these flags.
     *
     * @return the ACE flags
     */
    int getFlags();

    /**
     * Returns true if this ACE is an inherited ACE and false if it is a direct ACE.
     * <p>
     * Note: For reasons not fully understood, <code>FLAGS_INHERITED</code> may
     * not be set within all security descriptors even though the ACE was in
     * face inherited. If an inherited ACE is added to a parent the Windows
     * ACL editor will rebuild all children ACEs and set this flag accordingly.
     *
     * @return whether this is an inherited ACE
     */
    boolean isInherited();

    /**
     * Returns true if this ACE is an allow ACE and false if it is a deny ACE.
     *
     * @return whether this in an allow ACE
     */
    boolean isAllow();

}
