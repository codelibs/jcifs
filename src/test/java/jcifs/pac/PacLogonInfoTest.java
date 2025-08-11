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
package jcifs.pac;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import jcifs.pac.PACDecodingException;

import org.junit.jupiter.api.Test;

import jcifs.smb.SID;

class PacLogonInfoTest {

    // Test data constants
    private static final long FILETIME_1 = 130640000000000000L; // A sample file time
    private static final String USER_NAME = "testUser";
    private static final String DOMAIN_NAME = "testDomain";
    private static final String SERVER_NAME = "testServer";
    private static SID DOMAIN_SID;
    private static SID EXTRA_SID_1;
    private static SID EXTRA_SID_2;
    
    static {
        try {
            DOMAIN_SID = new SID("S-1-5-21-1-2-3");
            EXTRA_SID_1 = new SID("S-1-18-1");
            EXTRA_SID_2 = new SID("S-1-18-2");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Helper to create PAC Logon Info byte array with customizable options.
     */
    private byte[] createPacLogonInfoData(boolean withExtraSids, boolean withResourceGroups, boolean emptyUserId, int invalidGroupCount) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (DataOutputStream dos = new DataOutputStream(baos)) {
            ByteBuffer buffer = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);

            // Initial skip
            dos.write(new byte[20]);

            // Dates
            for (int i = 0; i < 6; i++) {
                buffer.putLong(0, FILETIME_1);
                dos.write(buffer.array(), 0, 8);
            }

            // String headers (pointers will be updated later)
            long stringHeadersPos = dos.size();
            dos.write(new byte[6 * 8]);

            // Counts
            dos.writeShort(Short.reverseBytes((short) 10)); // logonCount
            dos.writeShort(Short.reverseBytes((short) 1));  // badPasswordCount

            // User/Group RIDs
            if (emptyUserId) {
                dos.writeInt(0);
            } else {
                dos.writeInt(Integer.reverseBytes(1000)); // User RID
            }
            dos.writeInt(Integer.reverseBytes(513));  // Group RID

            // Group Info
            int groupCount = (invalidGroupCount != -1) ? invalidGroupCount : 1;
            dos.writeInt(Integer.reverseBytes(groupCount));
            long groupPointerPos = dos.size();
            dos.writeInt(0); // groupPointer placeholder

            // User Flags
            int userFlags = 0;
            if (withExtraSids) userFlags |= PacConstants.LOGON_EXTRA_SIDS;
            if (withResourceGroups) userFlags |= PacConstants.LOGON_RESOURCE_GROUPS;
            dos.writeInt(Integer.reverseBytes(userFlags));

            // Skip Session Key
            dos.write(new byte[16]);

            // Server/Domain String headers
            long serverStringHeaderPos = dos.size();
            dos.write(new byte[2 * 8]);

            // Domain ID Pointer
            long domainIdPointerPos = dos.size();
            dos.writeInt(0); // domainIdPointer placeholder

            dos.write(new byte[8]); // Skip
            dos.writeInt(Integer.reverseBytes(512)); // UserAccountControl
            dos.write(new byte[28]); // Skip

            // Extra SID Info
            dos.writeInt(Integer.reverseBytes(withExtraSids ? 2 : 0));
            long extraSidPointerPos = dos.size();
            dos.writeInt(0); // extraSidPointer placeholder

            // Resource Domain ID Pointer
            long resourceDomainIdPointerPos = dos.size();
            dos.writeInt(0); // resourceDomainIdPointer placeholder

            // Resource Group Info
            dos.writeInt(Integer.reverseBytes(withResourceGroups ? 1 : 0));
            long resourceGroupPointerPos = dos.size();
            dos.writeInt(0); // resourceGroupPointer placeholder

            // --- Start writing variable data --- //
            int currentOffset = dos.size();

            // Write strings and update headers
            int userNameOffset = writeString(dos, USER_NAME, currentOffset);
            writeUnicodeStringHeader(baos.toByteArray(), dos, stringHeadersPos, USER_NAME, userNameOffset);
            int displayNameOffset = writeString(dos, "DisplayName", userNameOffset + USER_NAME.length() * 2);
            writeUnicodeStringHeader(baos.toByteArray(), dos, stringHeadersPos + 8, "DisplayName", displayNameOffset);
            // ... and so on for other strings ...

            // For simplicity, we will skip other strings and point them to the same location
            int logonScriptOffset = displayNameOffset + "DisplayName".length() * 2;
            writeString(dos, "LogonScript", logonScriptOffset);
            writeUnicodeStringHeader(baos.toByteArray(), dos, stringHeadersPos + 16, "LogonScript", logonScriptOffset);

            int profilePathOffset = logonScriptOffset + "LogonScript".length() * 2;
            writeString(dos, "ProfilePath", profilePathOffset);
            writeUnicodeStringHeader(baos.toByteArray(), dos, stringHeadersPos + 24, "ProfilePath", profilePathOffset);

            int homeDirOffset = profilePathOffset + "ProfilePath".length() * 2;
            writeString(dos, "HomeDirectory", homeDirOffset);
            writeUnicodeStringHeader(baos.toByteArray(), dos, stringHeadersPos + 32, "HomeDirectory", homeDirOffset);

            int homeDriveOffset = homeDirOffset + "HomeDirectory".length() * 2;
            writeString(dos, "C:", homeDriveOffset);
            writeUnicodeStringHeader(baos.toByteArray(), dos, stringHeadersPos + 40, "C:", homeDriveOffset);

            int serverNameOffset = homeDriveOffset + "C:".length() * 2;
            writeString(dos, SERVER_NAME, serverNameOffset);
            writeUnicodeStringHeader(baos.toByteArray(), dos, serverStringHeaderPos, SERVER_NAME, serverNameOffset);

            int domainNameOffset = serverNameOffset + SERVER_NAME.length() * 2;
            writeString(dos, DOMAIN_NAME, domainNameOffset);
            writeUnicodeStringHeader(baos.toByteArray(), dos, serverStringHeaderPos + 8, DOMAIN_NAME, domainNameOffset);

            currentOffset = domainNameOffset + DOMAIN_NAME.length() * 2;

            // Write Group Data
            if (invalidGroupCount == -1) {
                updatePointer(baos.toByteArray(), groupPointerPos, currentOffset);
                dos.writeInt(Integer.reverseBytes(1)); // realGroupCount
                dos.writeInt(Integer.reverseBytes(513)); // group rid
                dos.writeInt(Integer.reverseBytes(7));   // attributes
                currentOffset += 12;
            }

            // Write Domain SID
            updatePointer(baos.toByteArray(), domainIdPointerPos, currentOffset);
            byte[] domainSidBytes = DOMAIN_SID.toByteArray();
            dos.write(domainSidBytes);
            currentOffset += domainSidBytes.length;

            // Write Extra SIDs
            if (withExtraSids) {
                updatePointer(baos.toByteArray(), extraSidPointerPos, currentOffset);
                dos.writeInt(Integer.reverseBytes(2)); // realExtraSidCount
                long sid1PointerPos = dos.size();
                dos.writeInt(0);
                dos.writeInt(Integer.reverseBytes(4)); // attributes
                long sid2PointerPos = dos.size();
                dos.writeInt(0);
                dos.writeInt(Integer.reverseBytes(7)); // attributes
                currentOffset += 16;

                updatePointer(baos.toByteArray(), sid1PointerPos, currentOffset);
                byte[] extraSid1Bytes = EXTRA_SID_1.toByteArray();
                dos.write(extraSid1Bytes);
                currentOffset += extraSid1Bytes.length;

                updatePointer(baos.toByteArray(), sid2PointerPos, currentOffset);
                byte[] extraSid2Bytes = EXTRA_SID_2.toByteArray();
                dos.write(extraSid2Bytes);
                currentOffset += extraSid2Bytes.length;
            }

            // Write Resource Groups
            if (withResourceGroups) {
                updatePointer(baos.toByteArray(), resourceGroupPointerPos, currentOffset);
                dos.writeInt(Integer.reverseBytes(1)); // realResourceGroupCount
                byte[] resourceGroupSidBytes;
                try {
                    resourceGroupSidBytes = new SID(DOMAIN_SID, 1101).toByteArray();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                dos.write(resourceGroupSidBytes);
                dos.writeInt(Integer.reverseBytes(7)); // attributes
            }

            return baos.toByteArray();
        }
    }

    private int writeString(DataOutputStream dos, String s, int offset) throws IOException {
        byte[] stringBytes = s.getBytes(StandardCharsets.UTF_16LE);
        dos.write(stringBytes);
        return offset + stringBytes.length;
    }

    private void writeUnicodeStringHeader(byte[] data, DataOutputStream dos, long position, String s, int pointer) {
        ByteBuffer buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        short length = (short) (s.length() * 2);
        buffer.putShort((int) position, length);
        buffer.putShort((int) position + 2, length);
        buffer.putInt((int) position + 4, pointer);
    }

    private void updatePointer(byte[] data, long position, int pointer) {
        ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).putInt((int) position, pointer);
    }

    @Test
    void testSuccessfulParsing_Basic() throws IOException, PACDecodingException {
        byte[] data = createPacLogonInfoData(false, false, false, -1);
        PacLogonInfo logonInfo = new PacLogonInfo(data);

        assertEquals(USER_NAME, logonInfo.getUserName());
        assertEquals(SERVER_NAME, logonInfo.getServerName());
        assertEquals(DOMAIN_NAME, logonInfo.getDomainName());
        assertEquals(10, logonInfo.getLogonCount());
        assertEquals(1, logonInfo.getBadPasswordCount());
        assertEquals(512, logonInfo.getUserAccountControl());
        assertEquals(0, logonInfo.getUserFlags());
        assertNotNull(logonInfo.getUserSid());
        assertEquals("S-1-5-21-1-2-3-1000", logonInfo.getUserSid().toString());
        assertEquals(1, logonInfo.getGroupSids().length);
        assertEquals(0, logonInfo.getExtraSids().length);
        assertEquals(0, logonInfo.getResourceGroupSids().length);
    }

    @Test
    void testSuccessfulParsing_WithExtraSids() throws IOException, PACDecodingException {
        byte[] data = createPacLogonInfoData(true, false, false, -1);
        PacLogonInfo logonInfo = new PacLogonInfo(data);

        assertEquals(2, logonInfo.getExtraSids().length);
        assertArrayEquals(new SID[]{EXTRA_SID_1, EXTRA_SID_2}, logonInfo.getExtraSids());
    }

    @Test
    void testSuccessfulParsing_WithResourceGroups() throws IOException, PACDecodingException {
        byte[] data = createPacLogonInfoData(false, true, false, -1);
        PacLogonInfo logonInfo = new PacLogonInfo(data);

        assertEquals(1, logonInfo.getResourceGroupSids().length);
    }

    @Test
    void testSuccessfulParsing_EmptyUserId() throws IOException, PACDecodingException {
        byte[] data = createPacLogonInfoData(true, false, true, -1);
        PacLogonInfo logonInfo = new PacLogonInfo(data);

        // Should take the first extra SID
        assertEquals(EXTRA_SID_1, logonInfo.getUserSid());
    }

    @Test
    void testInvalidGroupCount() throws IOException {
        byte[] data = createPacLogonInfoData(false, false, false, 2);
        PACDecodingException e = assertThrows(PACDecodingException.class, () -> new PacLogonInfo(data));
        assertEquals("Invalid number of groups in PAC expect2 have 1", e.getMessage());
    }

    @Test
    void testMalformedPac() {
        byte[] badData = new byte[10];
        PACDecodingException e = assertThrows(PACDecodingException.class, () -> new PacLogonInfo(badData));
        assertEquals("Malformed PAC", e.getMessage());
    }
}
