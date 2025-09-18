package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the SmbComQueryInformationResponse class.
 */
public class SmbComQueryInformationResponseTest {

    private SmbComQueryInformationResponse response;
    private final long serverTimeZoneOffset = 3600000; // 1 hour in milliseconds

    @BeforeEach
    public void setUp() {
        response = new SmbComQueryInformationResponse(serverTimeZoneOffset);
    }

    @Test
    @DisplayName("Constructor should initialize with command and server timezone offset")
    public void constructorShouldInitializeCorrectly() {
        // The constructor sets the command and serverTimeZoneOffset.
        // We can't directly access serverTimeZoneOffset, but we can verify its effect.
        assertEquals(ServerMessageBlock.SMB_COM_QUERY_INFORMATION, response.command);
        assertEquals(serverTimeZoneOffset, response.getLastWriteTime());
    }

    @Test
    @DisplayName("getAttributes should return zero initially")
    public void getAttributesShouldReturnZeroInitially() {
        // Initially, attributes should be 0.
        assertEquals(0, response.getAttributes());
    }

    @Test
    @DisplayName("getCreateTime should return server timezone offset initially")
    public void getCreateTimeShouldReturnServerTimezoneOffset() {
        // Initially, lastWriteTime is 0, so createTime should be just the offset.
        assertEquals(serverTimeZoneOffset, response.getCreateTime());
    }

    @Test
    @DisplayName("getLastWriteTime should return server timezone offset initially")
    public void getLastWriteTimeShouldReturnServerTimezoneOffset() {
        // Initially, lastWriteTime is 0, so it should return just the offset.
        assertEquals(serverTimeZoneOffset, response.getLastWriteTime());
    }

    @Test
    @DisplayName("getSize should return zero initially")
    public void getSizeShouldReturnZeroInitially() {
        // Initially, fileSize should be 0.
        assertEquals(0, response.getSize());
    }

    @Test
    @DisplayName("writeParameterWordsWireFormat should return zero")
    public void writeParameterWordsWireFormatShouldReturnZero() {
        byte[] dst = new byte[10];
        int dstIndex = 0;
        // This method does nothing and should return 0.
        assertEquals(0, response.writeParameterWordsWireFormat(dst, dstIndex));
    }

    @Test
    @DisplayName("writeBytesWireFormat should return zero")
    public void writeBytesWireFormatShouldReturnZero() {
        byte[] dst = new byte[10];
        int dstIndex = 0;
        // This method does nothing and should return 0.
        assertEquals(0, response.writeBytesWireFormat(dst, dstIndex));
    }

    @Test
    @DisplayName("readParameterWordsWireFormat should read file attributes, time and size")
    public void readParameterWordsWireFormatShouldReadFileData() {
        // Prepare a buffer with sample data.
        // 2 bytes for fileAttributes, 4 bytes for lastWriteTime, 4 bytes for fileSize
        byte[] buffer = new byte[20];
        // File Attributes: 0x0010 (Directory)
        buffer[0] = 0x10;
        buffer[1] = 0x00;
        // Last Write Time (UTime): A sample timestamp in milliseconds
        long sampleTimeMillis = 1672531200000L; // Represents a specific date in milliseconds
        ServerMessageBlock.writeUTime(sampleTimeMillis, buffer, 2);
        // File Size: 1024 bytes
        ServerMessageBlock.writeInt4(1024, buffer, 6);

        response.wordCount = 10; // Must be non-zero to read
        int bytesRead = response.readParameterWordsWireFormat(buffer, 0);

        // Should read 20 bytes as per implementation
        assertEquals(20, bytesRead);
        assertEquals(0x0010, response.getAttributes());
        // getLastWriteTime returns lastWriteTime (from readUTime) + serverTimeZoneOffset
        // readUTime multiplies the seconds value by 1000, and writeUTime divides milliseconds by 1000
        // So the round-trip should preserve the milliseconds value
        assertEquals(sampleTimeMillis + serverTimeZoneOffset, response.getLastWriteTime());
        assertEquals(1024, response.getSize());
    }

    @Test
    @DisplayName("readParameterWordsWireFormat should return zero with zero word count")
    public void readParameterWordsWireFormatWithZeroWordCountShouldReturnZero() {
        byte[] buffer = new byte[20];
        response.wordCount = 0;
        int bytesRead = response.readParameterWordsWireFormat(buffer, 0);
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("readBytesWireFormat should return zero")
    public void readBytesWireFormatShouldReturnZero() {
        byte[] buffer = new byte[10];
        int bufferIndex = 0;
        // This method does nothing and should return 0.
        assertEquals(0, response.readBytesWireFormat(buffer, bufferIndex));
    }

    @Test
    @DisplayName("toString should return properly formatted string representation")
    public void toStringShouldReturnFormattedRepresentation() {
        String result = response.toString();
        assertNotNull(result);
        assertTrue(result.startsWith("SmbComQueryInformationResponse["));
        assertTrue(result.contains("fileAttributes=0x0000"));
        assertTrue(result.contains("lastWriteTime=" + new Date(0L)));
        assertTrue(result.contains("fileSize=0"));
        assertTrue(result.endsWith("]"));
    }
}
