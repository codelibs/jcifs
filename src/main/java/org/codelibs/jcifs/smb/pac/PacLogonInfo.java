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
package org.codelibs.jcifs.smb.pac;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Date;

import org.codelibs.jcifs.smb.impl.SID;

/**
 * Contains user logon information from a PAC (Privilege Attribute Certificate).
 * This class parses and provides access to user authentication and authorization
 * data from Kerberos tickets, including user identity, group memberships, and
 * logon metadata.
 */
public class PacLogonInfo {

    private Date logonTime;
    private Date logoffTime;
    private Date kickOffTime;
    private Date pwdLastChangeTime;
    private Date pwdCanChangeTime;
    private Date pwdMustChangeTime;
    private short logonCount;
    private short badPasswordCount;
    private String userName;
    private String userDisplayName;
    private String logonScript;
    private String profilePath;
    private String homeDirectory;
    private String homeDrive;
    private String serverName;
    private String domainName;
    private SID userSid;
    private SID groupSid;
    private SID[] groupSids;
    private SID[] resourceGroupSids;
    private SID[] extraSids;
    private int userAccountControl;
    private int userFlags;

    /**
     * Constructs a PAC logon information object from raw PAC data.
     * @param data the raw PAC logon info buffer data
     * @throws PACDecodingException if the data is malformed or invalid
     */
    public PacLogonInfo(final byte[] data) throws PACDecodingException {
        try {
            final PacDataInputStream pacStream = new PacDataInputStream(new DataInputStream(new ByteArrayInputStream(data)));

            // Skip firsts
            pacStream.skipBytes(20);

            // Dates
            this.logonTime = pacStream.readFiletime();
            this.logoffTime = pacStream.readFiletime();
            this.kickOffTime = pacStream.readFiletime();
            this.pwdLastChangeTime = pacStream.readFiletime();
            this.pwdCanChangeTime = pacStream.readFiletime();
            this.pwdMustChangeTime = pacStream.readFiletime();

            // User related strings as UnicodeStrings
            final PacUnicodeString userNameString = pacStream.readUnicodeString();
            final PacUnicodeString userDisplayNameString = pacStream.readUnicodeString();
            final PacUnicodeString logonScriptString = pacStream.readUnicodeString();
            final PacUnicodeString profilePathString = pacStream.readUnicodeString();
            final PacUnicodeString homeDirectoryString = pacStream.readUnicodeString();
            final PacUnicodeString homeDriveString = pacStream.readUnicodeString();

            // Some counts
            this.logonCount = pacStream.readShort();
            this.badPasswordCount = pacStream.readShort();

            // IDs for user
            final SID userId = pacStream.readId();
            final SID groupId = pacStream.readId();

            // Groups information
            final int groupCount = pacStream.readInt();
            final int groupPointer = pacStream.readInt();

            // User flags about PAC Logon Info content
            this.userFlags = pacStream.readInt();
            final boolean hasExtraSids = (this.userFlags & PacConstants.LOGON_EXTRA_SIDS) == PacConstants.LOGON_EXTRA_SIDS;
            final boolean hasResourceGroups = (this.userFlags & PacConstants.LOGON_RESOURCE_GROUPS) == PacConstants.LOGON_RESOURCE_GROUPS;

            // Skip some reserved fields (User Session Key)
            pacStream.skipBytes(16);

            // Server related strings as UnicodeStrings
            final PacUnicodeString serverNameString = pacStream.readUnicodeString();
            final PacUnicodeString domainNameString = pacStream.readUnicodeString();

            // ID for domain (used with relative IDs to get SIDs)
            final int domainIdPointer = pacStream.readInt();

            // Skip some reserved fields
            pacStream.skipBytes(8);

            this.userAccountControl = pacStream.readInt();

            // Skip some reserved fields
            pacStream.skipBytes(28);

            // Extra SIDs information
            final int extraSidCount = pacStream.readInt();
            final int extraSidPointer = pacStream.readInt();

            // ID for resource groups domain (used with IDs to get SIDs)
            final int resourceDomainIdPointer = pacStream.readInt();

            // Resource groups information
            final int resourceGroupCount = pacStream.readInt();
            final int resourceGroupPointer = pacStream.readInt();

            // User related strings
            this.userName = userNameString.check(pacStream.readString());
            this.userDisplayName = userDisplayNameString.check(pacStream.readString());
            this.logonScript = logonScriptString.check(pacStream.readString());
            this.profilePath = profilePathString.check(pacStream.readString());
            this.homeDirectory = homeDirectoryString.check(pacStream.readString());
            this.homeDrive = homeDriveString.check(pacStream.readString());

            // Groups data
            PacGroup[] groups = {};
            if (groupPointer != 0) {
                final int realGroupCount = pacStream.readInt();
                if (realGroupCount != groupCount) {
                    throw new PACDecodingException("Invalid number of groups in PAC expect" + groupCount + " have " + realGroupCount);
                }
                groups = new PacGroup[groupCount];
                for (int i = 0; i < groupCount; i++) {
                    pacStream.align(4);
                    final SID id = pacStream.readId();
                    final int attributes = pacStream.readInt();
                    groups[i] = new PacGroup(id, attributes);
                }
            }

            // Server related strings
            this.serverName = serverNameString.check(pacStream.readString());
            this.domainName = domainNameString.check(pacStream.readString());

            // ID for domain (used with relative IDs to get SIDs)
            SID domainId = null;
            if (domainIdPointer != 0) {
                domainId = pacStream.readSid();
            }

            // Extra SIDs data
            PacSidAttributes[] extraSidAtts = {};
            if (hasExtraSids && extraSidPointer != 0) {
                final int realExtraSidCount = pacStream.readInt();
                if (realExtraSidCount != extraSidCount) {
                    throw new PACDecodingException("Invalid number of SIDs in PAC expect" + extraSidCount + " have " + realExtraSidCount);
                }
                extraSidAtts = new PacSidAttributes[extraSidCount];
                final int[] pointers = new int[extraSidCount];
                final int[] attributes = new int[extraSidCount];
                for (int i = 0; i < extraSidCount; i++) {
                    pointers[i] = pacStream.readInt();
                    attributes[i] = pacStream.readInt();
                }
                for (int i = 0; i < extraSidCount; i++) {
                    final SID sid = pointers[i] != 0 ? pacStream.readSid() : null;
                    extraSidAtts[i] = new PacSidAttributes(sid, attributes[i]);
                }
            }

            // ID for resource domain (used with relative IDs to get SIDs)
            SID resourceDomainId = null;
            if (resourceDomainIdPointer != 0) {
                resourceDomainId = pacStream.readSid();
            }

            // Resource groups data
            PacGroup[] resourceGroups = {};
            if (hasResourceGroups && resourceGroupPointer != 0) {
                final int realResourceGroupCount = pacStream.readInt();
                if (realResourceGroupCount != resourceGroupCount) {
                    throw new PACDecodingException(
                            "Invalid number of Resource Groups in PAC expect" + resourceGroupCount + " have " + realResourceGroupCount);
                }
                resourceGroups = new PacGroup[resourceGroupCount];
                for (int i = 0; i < resourceGroupCount; i++) {
                    final SID id = pacStream.readSid();
                    final int attributes = pacStream.readInt();
                    resourceGroups[i] = new PacGroup(id, attributes);
                }
            }

            // Extract Extra SIDs
            this.extraSids = new SID[extraSidAtts.length];
            for (int i = 0; i < extraSidAtts.length; i++) {
                this.extraSids[i] = extraSidAtts[i].getId();
            }

            // Compute Resource Group IDs with Resource Domain ID to get SIDs
            this.resourceGroupSids = new SID[resourceGroups.length];
            for (int i = 0; i < resourceGroups.length; i++) {
                this.resourceGroupSids[i] = new SID(resourceDomainId, resourceGroups[i].getId());
            }

            // Compute User IDs with Domain ID to get User SIDs
            // First extra is user if userId is empty
            if (!userId.isEmpty() && !userId.isBlank()) {
                this.userSid = new SID(domainId, userId);
            } else if (this.extraSids.length > 0) {
                this.userSid = this.extraSids[0];
            }
            this.groupSid = new SID(domainId, groupId);

            // Compute Group IDs with Domain ID to get Group SIDs
            this.groupSids = new SID[groups.length];
            for (int i = 0; i < groups.length; i++) {
                this.groupSids[i] = new SID(domainId, groups[i].getId());
            }
        } catch (final IOException e) {
            throw new PACDecodingException("Malformed PAC", e);
        }
    }

    /**
     * Returns the user's logon time.
     * @return the logon timestamp
     */
    public Date getLogonTime() {
        return this.logonTime;
    }

    /**
     * Returns the user's logoff time.
     * @return the logoff timestamp
     */
    public Date getLogoffTime() {
        return this.logoffTime;
    }

    /**
     * Returns the time when the user's session will be forcibly terminated.
     * @return the kick off timestamp
     */
    public Date getKickOffTime() {
        return this.kickOffTime;
    }

    /**
     * Returns the time when the user's password was last changed.
     * @return the password last change timestamp
     */
    public Date getPwdLastChangeTime() {
        return this.pwdLastChangeTime;
    }

    /**
     * Returns the earliest time when the user can change their password.
     * @return the password can change timestamp
     */
    public Date getPwdCanChangeTime() {
        return this.pwdCanChangeTime;
    }

    /**
     * Returns the time when the user must change their password.
     * @return the password must change timestamp
     */
    public Date getPwdMustChangeTime() {
        return this.pwdMustChangeTime;
    }

    /**
     * Returns the number of successful logons for this user.
     * @return the logon count
     */
    public short getLogonCount() {
        return this.logonCount;
    }

    /**
     * Returns the number of failed password attempts for this user.
     * @return the bad password count
     */
    public short getBadPasswordCount() {
        return this.badPasswordCount;
    }

    /**
     * Returns the user's account name.
     * @return the user name
     */
    public String getUserName() {
        return this.userName;
    }

    /**
     * Returns the user's display name.
     * @return the user display name
     */
    public String getUserDisplayName() {
        return this.userDisplayName;
    }

    /**
     * Returns the path to the user's logon script.
     * @return the logon script path
     */
    public String getLogonScript() {
        return this.logonScript;
    }

    /**
     * Returns the path to the user's profile.
     * @return the profile path
     */
    public String getProfilePath() {
        return this.profilePath;
    }

    /**
     * Returns the user's home directory path.
     * @return the home directory path
     */
    public String getHomeDirectory() {
        return this.homeDirectory;
    }

    /**
     * Returns the user's home drive letter.
     * @return the home drive
     */
    public String getHomeDrive() {
        return this.homeDrive;
    }

    /**
     * Returns the name of the server that authenticated the user.
     * @return the server name
     */
    public String getServerName() {
        return this.serverName;
    }

    /**
     * Returns the user's domain name.
     * @return the domain name
     */
    public String getDomainName() {
        return this.domainName;
    }

    /**
     * Returns the user's Security Identifier (SID).
     * @return the user SID
     */
    public SID getUserSid() {
        return this.userSid;
    }

    /**
     * Returns the user's primary group SID.
     * @return the primary group SID
     */
    public SID getGroupSid() {
        return this.groupSid;
    }

    /**
     * Returns an array of group SIDs the user belongs to.
     * @return the group SIDs array
     */
    public SID[] getGroupSids() {
        return this.groupSids;
    }

    /**
     * Returns an array of resource group SIDs the user belongs to.
     * @return the resource group SIDs array
     */
    public SID[] getResourceGroupSids() {
        return this.resourceGroupSids;
    }

    /**
     * Returns an array of extra SIDs associated with the user.
     * @return the extra SIDs array
     */
    public SID[] getExtraSids() {
        return this.extraSids;
    }

    /**
     * Returns the user account control flags.
     * @return the user account control value
     */
    public int getUserAccountControl() {
        return this.userAccountControl;
    }

    /**
     * Returns the user flags indicating PAC content.
     * @return the user flags value
     */
    public int getUserFlags() {
        return this.userFlags;
    }

}
