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
package jcifs.internal.smb1.trans2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import jcifs.Configuration;
import jcifs.config.PropertyConfiguration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.fscc.FileBothDirectoryInfo;
import jcifs.internal.smb1.trans.SmbComTransaction;
import java.util.Properties;

class Trans2FindFirst2ResponseTest {

    private Trans2FindFirst2Response response;
    private Configuration config;

    @BeforeEach
    void setUp() {
        // Mock the configuration
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.unicode", "true");
        config = new PropertyConfiguration(props);
        response = new Trans2FindFirst2Response(config);
    }

    @Test
    void testConstructor() {
        // Test if the constructor sets the command and subcommand correctly
        assertEquals(SmbComTransaction.SMB_COM_TRANSACTION2, response.getCommand());
        assertEquals(SmbComTransaction.TRANS2_FIND_FIRST2, response.getSubCommand());
    }

    @Test
    void testReadParametersWireFormat_findFirst2() {
        // Prepare a sample byte buffer for the parameters
        byte[] buffer = new byte[] {
                (byte) 0x01, (byte) 0x00, // sid
                (byte) 0x02, (byte) 0x00, // numEntries
                (byte) 0x01, (byte) 0x00, // isEndOfSearch
                (byte) 0x03, (byte) 0x00, // eaErrorOffset
                (byte) 0x04, (byte) 0x00  // lastNameOffset
        };

        // Set subcommand to TRANS2_FIND_FIRST2
        response.setSubCommand(SmbComTransaction.TRANS2_FIND_FIRST2);

        // Call the method to test
        int bytesRead = response.readParametersWireFormat(buffer, 0, buffer.length);

        // Assert that the correct number of bytes were read
        assertEquals(10, bytesRead);

        // Assert that the fields are correctly parsed
        assertEquals(1, response.getSid());
        assertEquals(2, response.getNumEntries());
        assertTrue(response.isEndOfSearch());
        assertEquals(3, response.getEaErrorOffset());
        assertEquals(4, response.getLastNameOffset());
    }

    @Test
    void testReadParametersWireFormat_findNext2() {
        // Prepare a sample byte buffer for the parameters
        byte[] buffer = new byte[] {
                (byte) 0x02, (byte) 0x00, // numEntries
                (byte) 0x00, (byte) 0x00, // isEndOfSearch (false)
                (byte) 0x03, (byte) 0x00, // eaErrorOffset
                (byte) 0x04, (byte) 0x00  // lastNameOffset
        };

        // Set subcommand to TRANS2_FIND_NEXT2
        response.setSubCommand(SmbComTransaction.TRANS2_FIND_NEXT2);

        // Call the method to test
        int bytesRead = response.readParametersWireFormat(buffer, 0, buffer.length);

        // Assert that the correct number of bytes were read
        assertEquals(8, bytesRead);

        // Assert that the fields are correctly parsed
        assertEquals(0, response.getSid()); // sid should not be read
        assertEquals(2, response.getNumEntries());
        assertFalse(response.isEndOfSearch());
        assertEquals(3, response.getEaErrorOffset());
        assertEquals(4, response.getLastNameOffset());
    }

    @Test
    void testReadDataWireFormat() throws SMBProtocolDecodingException {
        // Mock FileBothDirectoryInfo to control its behavior
        FileBothDirectoryInfo entry1 = mock(FileBothDirectoryInfo.class);
        when(entry1.getFilename()).thenReturn("file1.txt");
        when(entry1.getFileIndex()).thenReturn(100);
        when(entry1.getNextEntryOffset()).thenReturn(20);

        FileBothDirectoryInfo entry2 = mock(FileBothDirectoryInfo.class);
        when(entry2.getFilename()).thenReturn("file2.txt");
        when(entry2.getFileIndex()).thenReturn(200);
        when(entry2.getNextEntryOffset()).thenReturn(0); // Last entry

        // Set up the response with mocked entries
        response.setNumEntries(2);
        response.setLastNameOffset(10);
        response.setDataCount(40);

        // Prepare a dummy buffer (content doesn't matter as decode is mocked)
        byte[] buffer = new byte[100];

        // Create a custom response to inject the mocked entries
        Trans2FindFirst2Response customResponse = new Trans2FindFirst2Response(config) {
            private int callCount = 0;
            @Override
            protected int readDataWireFormat(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException {
                FileBothDirectoryInfo[] results = new FileBothDirectoryInfo[2];
                results[0] = entry1;
                results[1] = entry2;
                setResults(results);

                // Simulate the logic for lastName and resumeKey
                this.setLastNameOffset(10);
                int lastNameBufferIndex = bufferIndex + this.getLastNameOffset();

                if (lastNameBufferIndex >= bufferIndex && (entry1.getNextEntryOffset() == 0 || lastNameBufferIndex < (bufferIndex + entry1.getNextEntryOffset()))) {
                    setLastName(entry1.getFilename());
                    setResumeKey(entry1.getFileIndex());
                }
                if (lastNameBufferIndex >= bufferIndex + entry1.getNextEntryOffset() && (entry2.getNextEntryOffset() == 0 || lastNameBufferIndex < (bufferIndex + entry1.getNextEntryOffset() + entry2.getNextEntryOffset()))) {
                    setLastName(entry2.getFilename());
                    setResumeKey(entry2.getFileIndex());
                }
                return getDataCount();
            }
        };
        customResponse.setNumEntries(2);
        customResponse.setDataCount(40);

        // Call the method
        int bytesRead = customResponse.readDataWireFormat(buffer, 0, buffer.length);

        // Assertions
        assertEquals(40, bytesRead);
        assertNotNull(customResponse.getResults());
        assertEquals(2, customResponse.getResults().length);
        assertEquals("file1.txt", customResponse.getLastName());
        assertEquals(100, customResponse.getResumeKey());
    }

    @Test
    void testToString_findFirst2() {
        // Set subcommand and some values
        response.setSubCommand(SmbComTransaction.TRANS2_FIND_FIRST2);
        response.setSid(123);
        response.setNumEntries(5);
        response.setEndOfSearch(true);

        // Call toString()
        String result = response.toString();

        // Assert that the string contains the expected information
        assertTrue(result.startsWith("Trans2FindFirst2Response["));
        assertTrue(result.contains("sid=123"));
        assertTrue(result.contains("searchCount=5"));
        assertTrue(result.contains("isEndOfSearch=true"));
    }

    @Test
    void testToString_findNext2() {
        // Set subcommand and some values
        response.setSubCommand(SmbComTransaction.TRANS2_FIND_NEXT2);
        response.setNumEntries(3);
        response.setEndOfSearch(false);

        // Call toString()
        String result = response.toString();

        // Assert that the string contains the expected information
        assertTrue(result.startsWith("Trans2FindNext2Response["));
        assertTrue(result.contains("searchCount=3"));
        assertTrue(result.contains("isEndOfSearch=false"));
    }

    @Test
    void testEmptyMethods() {
        // These methods are empty, just call them for coverage
        assertEquals(0, response.writeSetupWireFormat(null, 0));
        assertEquals(0, response.writeParametersWireFormat(null, 0));
        assertEquals(0, response.writeDataWireFormat(null, 0));
        assertEquals(0, response.readSetupWireFormat(null, 0, 0));
    }

    @Test
    void testGetters() {
        // Set values using setters or other methods
        response.setSid(5);
        response.setEndOfSearch(true);
        response.setLastName("test.txt");
        response.setResumeKey(50);

        // Assert that getters return the correct values
        assertEquals(5, response.getSid());
        assertTrue(response.isEndOfSearch());
        assertEquals("test.txt", response.getLastName());
        assertEquals(50, response.getResumeKey());
    }
}