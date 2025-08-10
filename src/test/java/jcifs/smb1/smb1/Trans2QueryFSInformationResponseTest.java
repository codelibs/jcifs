/*
 * Copyright 2021 Shinsuke Ogawa
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

import jcifs.smb1.smb1.SmbComTransaction;
import jcifs.smb1.smb1.Trans2QueryFSInformationResponse;

/**
 * Tests for the Trans2QueryFSInformationResponse class.
 */
class Trans2QueryFSInformationResponseTest {

    /**
     * Tests the constructor to ensure it sets up the command and subcommand correctly.
     */
    @Test
    void testConstructor() {
        Trans2QueryFSInformationResponse response = new Trans2QueryFSInformationResponse(Trans2QueryFSInformationResponse.SMB_INFO_ALLOCATION);
        assertEquals(SmbComTransaction.SMB_COM_TRANSACTION2, response.command, "Command should be SMB_COM_TRANSACTION2");
        assertEquals(SmbComTransaction.TRANS2_QUERY_FS_INFORMATION, response.subCommand, "SubCommand should be TRANS2_QUERY_FS_INFORMATION");
    }

    /**
     * Tests the readDataWireFormat method with the SMB_INFO_ALLOCATION information level.
     */
    @Test
    void testReadDataWireFormat_SmbInfoAllocation() {
        Trans2QueryFSInformationResponse response = new Trans2QueryFSInformationResponse(Trans2QueryFSInformationResponse.SMB_INFO_ALLOCATION);
        byte[] buffer = new byte[20];
        // Mock data for SmbInfoAllocation
        // idFileSystem (4 bytes, skipped)
        writeInt4(100, buffer, 4);   // sectPerAlloc
        writeInt4(1000, buffer, 8);  // alloc
        writeInt4(500, buffer, 12);  // free
        writeInt2(512, buffer, 16);  // bytesPerSect

        int bytesRead = response.readDataWireFormat(buffer, 0, buffer.length);

        assertEquals(20, bytesRead, "Should read 20 bytes");
        assertNotNull(response.info, "Info object should not be null");
        assertTrue(response.info instanceof Trans2QueryFSInformationResponse.SmbInfoAllocation, "Info should be of type SmbInfoAllocation");

        Trans2QueryFSInformationResponse.SmbInfoAllocation info = (Trans2QueryFSInformationResponse.SmbInfoAllocation) response.info;
        assertEquals(1000, info.alloc);
        assertEquals(500, info.free);
        assertEquals(100, info.sectPerAlloc);
        assertEquals(512, info.bytesPerSect);
        assertEquals(1000L * 100 * 512, info.getCapacity(), "Capacity calculation should be correct");
        assertEquals(500L * 100 * 512, info.getFree(), "Free space calculation should be correct");
    }

    /**
     * Tests the readDataWireFormat method with the SMB_QUERY_FS_SIZE_INFO information level.
     */
    @Test
    void testReadDataWireFormat_SmbQueryFSSizeInfo() {
        Trans2QueryFSInformationResponse response = new Trans2QueryFSInformationResponse(Trans2QueryFSInformationResponse.SMB_QUERY_FS_SIZE_INFO);
        byte[] buffer = new byte[28];
        // Mock data for SmbQueryFSSizeInfo
        writeInt8(2000, buffer, 0);   // total allocation units
        writeInt8(1000, buffer, 8);   // free allocation units
        writeInt4(8, buffer, 16);     // sectors per allocation unit
        writeInt4(4096, buffer, 20);  // bytes per sector

        int bytesRead = response.readDataWireFormat(buffer, 0, buffer.length);

        assertEquals(24, bytesRead, "Should read 24 bytes");
        assertNotNull(response.info, "Info object should not be null");
        assertTrue(response.info instanceof Trans2QueryFSInformationResponse.SmbInfoAllocation, "Info should be of type SmbInfoAllocation");

        Trans2QueryFSInformationResponse.SmbInfoAllocation info = (Trans2QueryFSInformationResponse.SmbInfoAllocation) response.info;
        assertEquals(2000, info.alloc);
        assertEquals(1000, info.free);
        assertEquals(8, info.sectPerAlloc);
        assertEquals(4096, info.bytesPerSect);
        assertEquals(2000L * 8 * 4096, info.getCapacity(), "Capacity calculation should be correct");
        assertEquals(1000L * 8 * 4096, info.getFree(), "Free space calculation should be correct");
    }

    /**
     * Tests the readDataWireFormat method with the SMB_FS_FULL_SIZE_INFORMATION information level.
     */
    @Test
    void testReadDataWireFormat_FsFullSizeInformation() {
        Trans2QueryFSInformationResponse response = new Trans2QueryFSInformationResponse(Trans2QueryFSInformationResponse.SMB_FS_FULL_SIZE_INFORMATION);
        byte[] buffer = new byte[32];
        // Mock data for FsFullSizeInformation
        writeInt8(3000, buffer, 0);   // total allocation units
        writeInt8(1500, buffer, 8);   // caller available allocation units
        writeInt8(1500, buffer, 16);  // actual free units (skipped)
        writeInt4(4, buffer, 24);     // sectors per allocation unit
        writeInt4(8192, buffer, 28);  // bytes per sector

        int bytesRead = response.readDataWireFormat(buffer, 0, buffer.length);

        assertEquals(32, bytesRead, "Should read 32 bytes");
        assertNotNull(response.info, "Info object should not be null");
        assertTrue(response.info instanceof Trans2QueryFSInformationResponse.SmbInfoAllocation, "Info should be of type SmbInfoAllocation");

        Trans2QueryFSInformationResponse.SmbInfoAllocation info = (Trans2QueryFSInformationResponse.SmbInfoAllocation) response.info;
        assertEquals(3000, info.alloc);
        assertEquals(1500, info.free);
        assertEquals(4, info.sectPerAlloc);
        assertEquals(8192, info.bytesPerSect);
        assertEquals(3000L * 4 * 8192, info.getCapacity(), "Capacity calculation should be correct");
        assertEquals(1500L * 4 * 8192, info.getFree(), "Free space calculation should be correct");
    }

    /**
     * Tests the readDataWireFormat method with an unknown information level.
     */
    @Test
    void testReadDataWireFormat_UnknownInformationLevel() {
        Trans2QueryFSInformationResponse response = new Trans2QueryFSInformationResponse(999); // Unknown level
        byte[] buffer = new byte[10];
        int bytesRead = response.readDataWireFormat(buffer, 0, buffer.length);
        assertEquals(0, bytesRead, "Should read 0 bytes for unknown info level");
        assertNull(response.info, "Info object should be null for unknown info level");
    }

    /**
     * Tests the toString method of the Trans2QueryFSInformationResponse.
     */
    @Test
    void testToString() {
        Trans2QueryFSInformationResponse response = new Trans2QueryFSInformationResponse(Trans2QueryFSInformationResponse.SMB_INFO_ALLOCATION);
        String responseString = response.toString();
        assertTrue(responseString.startsWith("Trans2QueryFSInformationResponse["), "toString should start with the class name");
        // The toString implementation only includes the parent's toString, which may not include subCommand details
        assertNotNull(responseString);
        assertTrue(responseString.length() > 0);
    }

    /**
     * Tests the toString method of the nested SmbInfoAllocation class.
     */
    @Test
    void testSmbInfoAllocationToString() {
        Trans2QueryFSInformationResponse response = new Trans2QueryFSInformationResponse(Trans2QueryFSInformationResponse.SMB_INFO_ALLOCATION);
        Trans2QueryFSInformationResponse.SmbInfoAllocation info = response.new SmbInfoAllocation();
        info.alloc = 1000;
        info.free = 500;
        info.sectPerAlloc = 100;
        info.bytesPerSect = 512;

        String infoString = info.toString();
        assertTrue(infoString.contains("alloc=1000"), "toString should contain alloc");
        assertTrue(infoString.contains("free=500"), "toString should contain free");
        assertTrue(infoString.contains("sectPerAlloc=100"), "toString should contain sectPerAlloc");
        assertTrue(infoString.contains("bytesPerSect=512"), "toString should contain bytesPerSect");
    }

    // Helper methods to write numbers to byte array in little-endian format.
    private void writeInt2(int val, byte[] dst, int dstIndex) {
        dst[dstIndex++] = (byte) val;
        dst[dstIndex++] = (byte) (val >> 8);
    }

    private void writeInt4(int val, byte[] dst, int dstIndex) {
        dst[dstIndex++] = (byte) val;
        dst[dstIndex++] = (byte) (val >> 8);
        dst[dstIndex++] = (byte) (val >> 16);
        dst[dstIndex++] = (byte) (val >> 24);
    }

    private void writeInt8(long val, byte[] dst, int dstIndex) {
        dst[dstIndex++] = (byte) val;
        dst[dstIndex++] = (byte) (val >> 8);
        dst[dstIndex++] = (byte) (val >> 16);
        dst[dstIndex++] = (byte) (val >> 24);
        dst[dstIndex++] = (byte) (val >> 32);
        dst[dstIndex++] = (byte) (val >> 40);
        dst[dstIndex++] = (byte) (val >> 48);
        dst[dstIndex++] = (byte) (val >> 56);
    }
}