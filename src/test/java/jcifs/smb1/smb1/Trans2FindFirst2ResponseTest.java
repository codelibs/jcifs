package jcifs.smb1.smb1;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import jcifs.smb.SmbFile;

class Trans2FindFirst2ResponseTest {

    private Trans2FindFirst2Response response;

    @BeforeEach
    void setUp() {
        response = new Trans2FindFirst2Response();
    }

    // Test cases for SmbFindFileBothDirectoryInfo inner class
    @Test
    void testSmbFindFileBothDirectoryInfo_Getters() {
        Trans2FindFirst2Response.SmbFindFileBothDirectoryInfo info = response.new SmbFindFileBothDirectoryInfo();
        info.filename = "test.txt";
        info.extFileAttributes = SmbFile.ATTR_ARCHIVE;
        info.creationTime = 1672531200000L; // 2023-01-01
        info.lastWriteTime = 1672617600000L; // 2023-01-02
        info.endOfFile = 1024;

        assertEquals("test.txt", info.getName());
        assertEquals(SmbFile.TYPE_FILESYSTEM, info.getType());
        assertEquals(SmbFile.ATTR_ARCHIVE, info.getAttributes());
        assertEquals(1672531200000L, info.createTime());
        assertEquals(1672617600000L, info.lastModified());
        assertEquals(1024, info.length());
    }

    @Test
    void testSmbFindFileBothDirectoryInfo_ToString() {
        Trans2FindFirst2Response.SmbFindFileBothDirectoryInfo info = response.new SmbFindFileBothDirectoryInfo();
        info.filename = "test.txt";
        info.shortName = "TEST.TXT";
        info.nextEntryOffset = 1;
        info.fileIndex = 2;
        info.creationTime = 1672531200000L;
        info.lastAccessTime = 1672531200001L;
        info.lastWriteTime = 1672617600000L;
        info.changeTime = 1672617600001L;
        info.endOfFile = 1024;
        info.allocationSize = 2048;
        info.extFileAttributes = SmbFile.ATTR_READONLY;
        info.fileNameLength = 8;
        info.eaSize = 0;
        info.shortNameLength = 8;
        
        String expected = "SmbFindFileBothDirectoryInfo[" +
                "nextEntryOffset=" + info.nextEntryOffset +
                ",fileIndex=" + info.fileIndex +
                ",creationTime=" + new Date(info.creationTime) +
                ",lastAccessTime=" + new Date(info.lastAccessTime) +
                ",lastWriteTime=" + new Date(info.lastWriteTime) +
                ",changeTime=" + new Date(info.changeTime) +
                ",endOfFile=" + info.endOfFile +
                ",allocationSize=" + info.allocationSize +
                ",extFileAttributes=" + info.extFileAttributes +
                ",fileNameLength=" + info.fileNameLength +
                ",eaSize=" + info.eaSize +
                ",shortNameLength=" + info.shortNameLength +
                ",shortName=" + info.shortName +
                ",filename=" + info.filename + "]";
        assertEquals(expected, info.toString());
    }

    // Test cases for Trans2FindFirst2Response class
    @Test
    void testReadString_Unicode() throws UnsupportedEncodingException {
        response.useUnicode = true;
        String expected = "test";
        byte[] src = expected.getBytes("UTF-16LE");
        String result = response.readString(src, 0, src.length);
        assertEquals(expected, result);
    }

    @Test
    void testReadString_Oem() {
        response.useUnicode = false;
        String expected = "test";
        // Simulate OEM encoding with a null terminator
        byte[] src = (expected + "\0").getBytes(StandardCharsets.UTF_8);
        String result = response.readString(src, 0, src.length);
        // The method should remove the null terminator
        assertEquals(expected, result.substring(0, expected.length()));
    }
    
    @Test
    void testReadString_Oem_NoNullTerminator() {
        response.useUnicode = false;
        String expected = "test";
        byte[] src = expected.getBytes(StandardCharsets.UTF_8);
        String result = response.readString(src, 0, src.length);
        assertEquals(expected, result);
    }

    @Test
    void testReadParametersWireFormat_FindFirst2() {
        response.subCommand = SmbComTransaction.TRANS2_FIND_FIRST2;
        byte[] buffer = new byte[10];
        // sid = 1
        writeInt2(1, buffer, 0);
        // numEntries = 2
        writeInt2(2, buffer, 2);
        // isEndOfSearch = true
        buffer[4] = 0x01;
        buffer[5] = 0x00;
        // eaErrorOffset = 3
        writeInt2(3, buffer, 6);
        // lastNameOffset = 4
        writeInt2(4, buffer, 8);

        int bytesRead = response.readParametersWireFormat(buffer, 0, buffer.length);
        assertEquals(10, bytesRead);
        assertEquals(1, response.sid);
        assertEquals(2, response.numEntries);
        assertTrue(response.isEndOfSearch);
        assertEquals(3, response.eaErrorOffset);
        assertEquals(4, response.lastNameOffset);
    }
    
    @Test
    void testReadParametersWireFormat_FindNext2() {
        // In FindNext2, sid is not read
        response.subCommand = SmbComTransaction.TRANS2_FIND_NEXT2;
        byte[] buffer = new byte[8];
        // numEntries = 2
        writeInt2(2, buffer, 0);
        // isEndOfSearch = false
        buffer[2] = 0x00;
        buffer[3] = 0x00;
        // eaErrorOffset = 3
        writeInt2(3, buffer, 4);
        // lastNameOffset = 4
        writeInt2(4, buffer, 6);

        int bytesRead = response.readParametersWireFormat(buffer, 0, buffer.length);
        assertEquals(8, bytesRead);
        assertEquals(2, response.numEntries);
        assertFalse(response.isEndOfSearch);
        assertEquals(3, response.eaErrorOffset);
        assertEquals(4, response.lastNameOffset);
    }

    @Test
    void testReadDataWireFormat() {
        response.numEntries = 1;
        response.lastNameOffset = 94; // Pointing to the start of the filename
        response.useUnicode = false; // Use OEM for simplicity
        
        byte[] buffer = new byte[120];
        int bufferIndex = 0;

        // Entry 1
        writeInt4(120, buffer, bufferIndex); // nextEntryOffset = 120 (relative)
        writeInt4(1, buffer, bufferIndex + 4); // fileIndex = 1
        writeTime(1672531200000L, buffer, bufferIndex + 8); // creationTime
        writeTime(1672617600000L, buffer, bufferIndex + 24); // lastWriteTime
        writeInt8(2048, buffer, bufferIndex + 40); // endOfFile
        writeInt4(SmbFile.ATTR_DIRECTORY, buffer, bufferIndex + 56); // extFileAttributes
        
        String filename = "directory1";
        byte[] filenameBytes = filename.getBytes(StandardCharsets.UTF_8);
        writeInt4(filenameBytes.length, buffer, bufferIndex + 60); // fileNameLength
        
        // Copy filename into buffer at offset 94
        System.arraycopy(filenameBytes, 0, buffer, 94, filenameBytes.length);

        response.dataCount = 120;
        int bytesRead = response.readDataWireFormat(buffer, 0, buffer.length);

        assertEquals(response.dataCount, bytesRead);
        assertEquals(1, response.results.length);
        
        Trans2FindFirst2Response.SmbFindFileBothDirectoryInfo info = (Trans2FindFirst2Response.SmbFindFileBothDirectoryInfo) response.results[0];
        assertEquals(1, info.fileIndex);
        assertEquals(2048, info.endOfFile);
        assertEquals(SmbFile.ATTR_DIRECTORY, info.getAttributes());
        assertEquals(filename, info.getName());
        assertEquals(filename, response.lastName);
        assertEquals(1, response.resumeKey);
    }

    @Test
    void testEmptyWireFormatMethods() {
        byte[] dst = new byte[0];
        assertEquals(0, response.writeSetupWireFormat(dst, 0));
        assertEquals(0, response.writeParametersWireFormat(dst, 0));
        assertEquals(0, response.writeDataWireFormat(dst, 0));
        assertEquals(0, response.readSetupWireFormat(dst, 0, 0));
    }

    @Test
    void testToString_FindFirst2() {
        response.subCommand = SmbComTransaction.TRANS2_FIND_FIRST2;
        response.sid = 123;
        response.numEntries = 5;
        response.isEndOfSearch = true;
        response.eaErrorOffset = 0;
        response.lastNameOffset = 100;
        response.lastName = "file5.txt";
        
        String actual = response.toString();
        assertTrue(actual.startsWith("Trans2FindFirst2Response["));
        assertTrue(actual.contains("sid=123"));
        assertTrue(actual.contains("searchCount=5"));
        assertTrue(actual.contains("isEndOfSearch=true"));
        assertTrue(actual.contains("lastName=file5.txt"));
        assertTrue(actual.endsWith("]"));
    }
    
    @Test
    void testToString_FindNext2() {
        response.subCommand = SmbComTransaction.TRANS2_FIND_NEXT2;
        String actual = response.toString();
        assertTrue(actual.startsWith("Trans2FindNext2Response["));
    }

    // Helper methods to write data to byte arrays for testing read methods
    private void writeInt2(int val, byte[] dst, int dstIndex) {
        dst[dstIndex] = (byte) val;
        dst[dstIndex + 1] = (byte) (val >> 8);
    }

    private void writeInt4(int val, byte[] dst, int dstIndex) {
        dst[dstIndex] = (byte) val;
        dst[dstIndex + 1] = (byte) (val >> 8);
        dst[dstIndex + 2] = (byte) (val >> 16);
        dst[dstIndex + 3] = (byte) (val >> 24);
    }
    
    private void writeInt8(long val, byte[] dst, int dstIndex) {
        writeInt4((int)(val & 0xFFFFFFFFL), dst, dstIndex);
        writeInt4((int)(val >> 32), dst, dstIndex + 4);
    }

    private void writeTime(long t, byte[] dst, int dstIndex) {
        writeInt8(t, dst, dstIndex);
    }
}
