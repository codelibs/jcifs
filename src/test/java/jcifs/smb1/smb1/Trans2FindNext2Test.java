/*
 * Copyright 2024 Shinsuke Ogawa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package jcifs.smb1.smb1;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the Trans2FindNext2 class.
 */
class Trans2FindNext2Test {

    /**
     * Verifies constructor initializes protocol fields and limits correctly.
     */
    @Test
    void testConstructorInitializesFields() {
        // Given
        int sid = 0x2222;
        int resumeKey = 0x12345678;
        String filename = "dir\\pattern*";

        // When
        Trans2FindNext2 next = new Trans2FindNext2(sid, resumeKey, filename);

        // Then
        assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION2, next.command, "Command must be SMB_COM_TRANSACTION2");
        assertEquals(SmbComTransaction.TRANS2_FIND_NEXT2, next.subCommand, "Sub-command must be TRANS2_FIND_NEXT2");
        assertEquals(8, next.maxParameterCount, "Max parameter count should be 8");
        assertEquals(Trans2FindFirst2.LIST_SIZE, next.maxDataCount, "Max data count should use LIST_SIZE");
        assertEquals((byte) 0x00, next.maxSetupCount, "Max setup count must be 0");

        // Information level defaults to BOTH_DIRECTORY_INFO (0x104) — check via parameters encoding
        byte[] buf = new byte[2 + 2 + 2 + 4 + 2 + filename.length() + 1];
        int n = next.writeParametersWireFormat(buf, 0);
        assertEquals(buf.length, n, "Parameter bytes written should match expected length");
        // informationLevel LE at offset 4..5
        assertEquals((byte) 0x04, buf[4]);
        assertEquals((byte) 0x01, buf[5]);
    }

    /**
     * Ensures writeSetupWireFormat writes subcommand and trailing zero, returning 2.
     */
    @Test
    void testWriteSetupWireFormat() {
        // Given
        Trans2FindNext2 next = new Trans2FindNext2(0x1111, 0, "*");
        byte[] dst = new byte[2];

        // When
        int written = next.writeSetupWireFormat(dst, 0);

        // Then
        assertEquals(2, written, "Should write 2 bytes");
        assertEquals(SmbComTransaction.TRANS2_FIND_NEXT2, dst[0], "First byte must be subCommand");
        assertEquals((byte) 0x00, dst[1], "Second byte must be 0");
    }

    /**
     * Validates writeParametersWireFormat encodes values in the correct order and endianness.
     */
    @Test
    void testWriteParametersWireFormat() {
        // Given
        int sid = 0x1234;
        int resumeKey = 0x89ABCDEF; // LE expected: EF CD AB 89
        String name = "file.txt";
        Trans2FindNext2 next = new Trans2FindNext2(sid, resumeKey, name);

        int expectedLen = 2 + 2 + 2 + 4 + 2 + name.length() + 1;
        byte[] dst = new byte[expectedLen];

        // When
        int len = next.writeParametersWireFormat(dst, 0);

        // Then
        assertEquals(expectedLen, len, "Unexpected parameters length");

        // sid (2 bytes, LE)
        assertEquals((byte) 0x34, dst[0]);
        assertEquals((byte) 0x12, dst[1]);

        // LIST_COUNT (2 bytes, LE)
        int listCount = Trans2FindFirst2.LIST_COUNT;
        assertEquals((byte) (listCount & 0xFF), dst[2]);
        assertEquals((byte) ((listCount >> 8) & 0xFF), dst[3]);

        // informationLevel (2 bytes, LE) -> 0x0104
        assertEquals((byte) 0x04, dst[4]);
        assertEquals((byte) 0x01, dst[5]);

        // resumeKey (4 bytes, LE)
        assertEquals((byte) 0xEF, dst[6]);
        assertEquals((byte) 0xCD, dst[7]);
        assertEquals((byte) 0xAB, dst[8]);
        assertEquals((byte) 0x89, dst[9]);

        // flags (2 bytes, LE) -> 0x0000
        assertEquals((byte) 0x00, dst[10]);
        assertEquals((byte) 0x00, dst[11]);

        // filename bytes, then null terminator
        byte[] nameBytes = name.getBytes();
        for (int i = 0; i < nameBytes.length; i++) {
            assertEquals(nameBytes[i], dst[12 + i], "Filename byte mismatch at index " + i);
        }
        assertEquals((byte) 0x00, dst[12 + nameBytes.length], "Filename must be null-terminated");
    }

    /**
     * Verifies reset() clears flags2 and updates resumeKey and filename used for parameters.
     */
    @Test
    void testResetUpdatesStateAndParameters() {
        // Given
        Trans2FindNext2 next = new Trans2FindNext2(0x0001, 0x0AAA0BBB, "old");
        next.flags2 = 0xFFFF; // simulate non-zero flags2

        // When
        next.reset(0x11121314, "last.dat");

        // Then
        assertEquals(0, next.flags2, "flags2 should be reset to 0");

        // Verify parameters use updated resumeKey and filename
        String updatedName = "last.dat";
        byte[] dst = new byte[2 + 2 + 2 + 4 + 2 + updatedName.length() + 1];
        int n = next.writeParametersWireFormat(dst, 0);
        assertEquals(dst.length, n);

        // resumeKey (LE) at offset 6..9 should be 0x11121314 -> 14 13 12 11
        assertEquals((byte) 0x14, dst[6]);
        assertEquals((byte) 0x13, dst[7]);
        assertEquals((byte) 0x12, dst[8]);
        assertEquals((byte) 0x11, dst[9]);

        // filename content
        byte[] nameBytes = updatedName.getBytes();
        for (int i = 0; i < nameBytes.length; i++) {
            assertEquals(nameBytes[i], dst[12 + i]);
        }
        assertEquals((byte) 0x00, dst[12 + nameBytes.length]);
    }

    /**
     * read*WireFormat methods in request return 0 (not implemented for requests).
     */
    @Test
    void testReadWireFormatStubsReturnZero() {
        // Given
        Trans2FindNext2 next = new Trans2FindNext2(0x0101, 0, "name");
        byte[] buf = new byte[16];

        // When/Then
        assertEquals(0, next.readSetupWireFormat(buf, 0, buf.length));
        assertEquals(0, next.readParametersWireFormat(buf, 0, buf.length));
        assertEquals(0, next.readDataWireFormat(buf, 0, buf.length));
        assertEquals(0, next.writeDataWireFormat(buf, 0));
    }

    /**
     * Ensures toString contains key fields with expected formatting.
     */
    @Test
    void testToStringContainsExpectedFields() {
        // Given
        int sid = 4660; // 0x1234, printed as decimal
        int resumeKey = 0x01020304; // shows only low 4 hex digits per implementation
        String name = "name";
        Trans2FindNext2 next = new Trans2FindNext2(sid, resumeKey, name);

        // When
        String s = next.toString();

        // Then
        assertTrue(s.startsWith("Trans2FindNext2["), "toString should start with class name");
        assertTrue(s.contains(",sid=" + sid), "toString should include sid in decimal");
        assertTrue(s.contains(",searchCount=" + Trans2FindFirst2.LIST_SIZE), "toString should include searchCount using LIST_SIZE");
        assertTrue(s.contains(",informationLevel=0x104"), "toString should include information level 0x104");
        assertTrue(s.contains(",resumeKey=0x0304"), "toString should include lower 16-bit resumeKey hex");
        assertTrue(s.contains(",flags=0x00"), "toString should include flags in hex");
        assertTrue(s.endsWith("]"), "toString should end with closing bracket");
    }
}

