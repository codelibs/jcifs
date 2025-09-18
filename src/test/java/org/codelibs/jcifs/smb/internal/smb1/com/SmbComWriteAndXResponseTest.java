package org.codelibs.jcifs.smb.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SmbComWriteAndXResponseTest {

    private Configuration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        config = new PropertyConfiguration(new Properties());
    }

    @Test
    @DisplayName("readParameterWordsWireFormat should read count correctly")
    public void readParameterWordsWireFormatShouldReadCount() {
        // Given
        byte[] buffer = new byte[] { (byte) 0xff, (byte) 0xff, 0, 0, 0, 0, 0, 0 };
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        int result = instance.readParameterWordsWireFormat(buffer, 0);

        // Then
        assertEquals(8, result);
        assertEquals(0xffffL, instance.getCount());
    }

    @Test
    @DisplayName("readParameterWordsWireFormat should handle zero count")
    public void readParameterWordsWireFormatShouldHandleZeroCount() {
        // Given
        byte[] buffer = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        int result = instance.readParameterWordsWireFormat(buffer, 0);

        // Then
        assertEquals(8, result);
        assertEquals(0L, instance.getCount());
    }

    @Test
    @DisplayName("writeParameterWordsWireFormat should return 0")
    public void writeParameterWordsWireFormatShouldReturnZero() {
        // Given
        byte[] buffer = new byte[10];
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        int result = instance.writeParameterWordsWireFormat(buffer, 0);

        // Then
        assertEquals(0, result);
    }

    @Test
    @DisplayName("writeBytesWireFormat should return 0")
    public void writeBytesWireFormatShouldReturnZero() {
        // Given
        byte[] buffer = new byte[10];
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        int result = instance.writeBytesWireFormat(buffer, 0);

        // Then
        assertEquals(0, result);
    }

    @Test
    @DisplayName("readBytesWireFormat should return 0")
    public void readBytesWireFormatShouldReturnZero() {
        // Given
        byte[] buffer = new byte[10];
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        int result = instance.readBytesWireFormat(buffer, 0);

        // Then
        assertEquals(0, result);
    }

    @Test
    @DisplayName("toString should contain class name and count")
    public void toStringShouldContainClassNameAndCount() {
        // Given
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        String result = instance.toString();

        // Then
        assertNotNull(result);
        assertTrue(result.contains("SmbComWriteAndXResponse"));
        assertTrue(result.contains("count=0"));
    }
}
