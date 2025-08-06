/*
 * Copyright 2024 The JCIFS Project
 *
 * The JCIFS Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package jcifs.smb1.smb1;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jcifs.smb1.util.Hexdump;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class SmbComDeleteTest {

    private static final String TEST_FILE_NAME = "testFile.txt";
    private SmbComDelete smbComDelete;

    @BeforeEach
    public void setUp() {
        smbComDelete = new SmbComDelete(TEST_FILE_NAME);
    }

    @Test
    public void testConstructor() {
        // Test if the constructor sets the file name and command correctly
        assertEquals(TEST_FILE_NAME, smbComDelete.path);
        assertEquals(ServerMessageBlock.SMB_COM_DELETE, smbComDelete.command);
    }

    @Test
    public void testWriteParameterWordsWireFormat() {
        // Test the writing of parameter words to a byte array
        byte[] dst = new byte[2];
        int bytesWritten = smbComDelete.writeParameterWordsWireFormat(dst, 0);
        assertEquals(2, bytesWritten);
        // ATTR_HIDDEN (0x02) | ATTR_SYSTEM (0x04) = 0x06
        assertEquals(0x06, dst[0]);
        assertEquals(0x00, dst[1]);
    }

    @Test
    public void testWriteBytesWireFormat() {
        // Test the writing of bytes to a byte array
        byte[] dst = new byte[100];
        int bytesWritten = smbComDelete.writeBytesWireFormat(dst, 0);

        // Expected format: buffer format (1 byte) + file name (null-terminated)
        int expectedLength = 1 + TEST_FILE_NAME.length() + 1;
        assertEquals(expectedLength, bytesWritten);
        assertEquals(0x04, dst[0]); // Buffer format
        assertEquals(TEST_FILE_NAME, new String(dst, 1, TEST_FILE_NAME.length()));
    }

    @Test
    public void testReadParameterWordsWireFormat() {
        // This method is expected to do nothing and return 0
        int result = smbComDelete.readParameterWordsWireFormat(new byte[0], 0);
        assertEquals(0, result);
    }

    @Test
    public void testReadBytesWireFormat() {
        // This method is expected to do nothing and return 0
        int result = smbComDelete.readBytesWireFormat(new byte[0], 0);
        assertEquals(0, result);
    }

    @Test
    public void testToString() {
        // Test the string representation of the object
        String result = smbComDelete.toString();
        assertNotNull(result);
        String expectedSearchAttributes = "searchAttributes=0x" + Hexdump.toHexString(smbComDelete.searchAttributes, 4);
        String expectedFileName = "fileName=" + TEST_FILE_NAME;

        assertEquals("SmbComDelete[" + smbComDelete.superToString() + "," + expectedSearchAttributes + "," + expectedFileName + "]", result);
    }
}
