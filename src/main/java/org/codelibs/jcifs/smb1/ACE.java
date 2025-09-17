package org.codelibs.jcifs.smb1;

import org.codelibs.jcifs.smb1.util.Hexdump;

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
 * <pre>
 * Allow WNET\alice     0x001200A9  Direct
 * Allow Administrators 0x001F01FF  Inherited
 * Allow SYSTEM         0x001F01FF  Inherited
 * </pre>
 * the access check would fail because the direct ACE has an access mask
 * of <code>0x001200A9</code> which doesn't have the
 * <code>FILE_WRITE_DATA</code> bit on (bit <code>0x00000002</code>). Actually, this isn't quite correct. If
 * <code>WNET\alice</code> is in the local <code>Administrators</code> group the access check
 * will succeed because the inherited ACE allows local <code>Administrators</code>
 * both <code>FILE_READ_DATA</code> and <code>FILE_WRITE_DATA</code> access.
 */

public class ACE {

    /**
     * Default constructor for ACE
     */
    public ACE() {
        // Default constructor
    }

    /** Permission to read data from a file or list directory contents */
    public static final int FILE_READ_DATA = 0x00000001; // 1
    /** Permission to write data to a file or add files to a directory */
    public static final int FILE_WRITE_DATA = 0x00000002; // 2
    /** Permission to append data to a file or add subdirectories */
    public static final int FILE_APPEND_DATA = 0x00000004; // 3
    /** Permission to read extended attributes */
    public static final int FILE_READ_EA = 0x00000008; // 4
    /** Permission to write extended attributes */
    public static final int FILE_WRITE_EA = 0x00000010; // 5
    /** Permission to execute a file or traverse a directory */
    public static final int FILE_EXECUTE = 0x00000020; // 6
    /** Permission to delete a file or directory */
    public static final int FILE_DELETE = 0x00000040; // 7
    /** Permission to read file attributes */
    public static final int FILE_READ_ATTRIBUTES = 0x00000080; // 8
    /** Permission to write file attributes */
    public static final int FILE_WRITE_ATTRIBUTES = 0x00000100; // 9
    /** Standard delete permission */
    public static final int DELETE = 0x00010000; // 16
    /** Permission to read the security descriptor */
    public static final int READ_CONTROL = 0x00020000; // 17
    /** Permission to write the discretionary access control list */
    public static final int WRITE_DAC = 0x00040000; // 18
    /** Permission to change the owner in the security descriptor */
    public static final int WRITE_OWNER = 0x00080000; // 19
    /** Permission to synchronize with the file */
    public static final int SYNCHRONIZE = 0x00100000; // 20
    /** Generic all permissions */
    public static final int GENERIC_ALL = 0x10000000; // 28
    /** Generic execute permission */
    public static final int GENERIC_EXECUTE = 0x20000000; // 29
    /** Generic write permission */
    public static final int GENERIC_WRITE = 0x40000000; // 30
    /** Generic read permission */
    public static final int GENERIC_READ = 0x80000000; // 31

    /** Inheritance flag: child objects inherit this ACE */
    public static final int FLAGS_OBJECT_INHERIT = 0x01;
    /** Inheritance flag: child containers inherit this ACE */
    public static final int FLAGS_CONTAINER_INHERIT = 0x02;
    /** Inheritance flag: inheritance stops after one level */
    public static final int FLAGS_NO_PROPAGATE = 0x04;
    /** Inheritance flag: ACE applies only to children, not to the object itself */
    public static final int FLAGS_INHERIT_ONLY = 0x08;
    /** Inheritance flag: ACE was inherited from parent */
    public static final int FLAGS_INHERITED = 0x10;

    boolean allow;
    int flags;
    int access;
    SID sid;

    /**
     * Returns true if this ACE is an allow ACE and false if it is a deny ACE.
     * @return true if this is an allow ACE, false if it is a deny ACE
     */
    public boolean isAllow() {
        return allow;
    }

    /**
     * Returns true if this ACE is an inherited ACE and false if it is a direct ACE.
     * <p>
     * Note: For reasons not fully understood, <code>FLAGS_INHERITED</code> may
     * not be set within all security descriptors even though the ACE was in
     * face inherited. If an inherited ACE is added to a parent the Windows
     * ACL editor will rebuild all children ACEs and set this flag accordingly.
     * @return true if this ACE is inherited, false if it is direct
     */
    public boolean isInherited() {
        return (flags & FLAGS_INHERITED) != 0;
    }

    /**
     * Returns the flags for this ACE. The <code>isInherited()</code>
     * method checks the <code>FLAGS_INHERITED</code> bit in these flags.
     * @return the ACE flags
     */
    public int getFlags() {
        return flags;
    }

    /**
     * Returns the 'Apply To' text for inheritance of ACEs on
     * directories such as 'This folder, subfolder and files'. For
     * files the text is always 'This object only'.
     * @return the text describing what this ACE applies to
     */
    public String getApplyToText() {
        switch (flags & (FLAGS_OBJECT_INHERIT | FLAGS_CONTAINER_INHERIT | FLAGS_INHERIT_ONLY)) {
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

    /**
     * Returns the access mask accociated with this ACE. Use the
     * constants for <code>FILE_READ_DATA</code>, <code>FILE_WRITE_DATA</code>,
     * <code>READ_CONTROL</code>, <code>GENERIC_ALL</code>, etc with bitwise
     * operators to determine which bits of the mask are on or off.
     * @return the access mask for this ACE
     */
    public int getAccessMask() {
        return access;
    }

    /**
     * Return the SID associated with this ACE.
     * @return the SID for this ACE
     */
    public SID getSID() {
        return sid;
    }

    int decode(final byte[] buf, int bi) {
        allow = buf[bi] == (byte) 0x00;
        bi++;
        flags = buf[bi++] & 0xFF;
        final int size = ServerMessageBlock.readInt2(buf, bi);
        bi += 2;
        access = ServerMessageBlock.readInt4(buf, bi);
        bi += 4;
        sid = new SID(buf, bi);
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
        final int count, i;
        final String str;

        final StringBuffer sb = new StringBuffer();
        sb.append(isAllow() ? "Allow " : "Deny  ");
        appendCol(sb, sid.toDisplayString(), 25);
        sb.append(" 0x").append(Hexdump.toHexString(access, 8)).append(' ');
        sb.append(isInherited() ? "Inherited " : "Direct    ");
        appendCol(sb, getApplyToText(), 34);
        return sb.toString();
    }
}
