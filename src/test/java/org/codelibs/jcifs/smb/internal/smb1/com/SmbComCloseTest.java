package org.codelibs.jcifs.smb.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.internal.smb1.SMB1SigningDigest;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link SmbComClose} class.
 */
public class SmbComCloseTest {

    private CIFSContext context;
    private PropertyConfiguration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        // Create a mock configuration for testing
        Properties properties = new Properties();
        config = new PropertyConfiguration(properties);
        context = mock(CIFSContext.class);
        when(context.getConfig()).thenReturn(config);
    }

    @Test
    @DisplayName("Verify constructor initializes SmbComClose with correct command")
    public void shouldInitializeWithCorrectCommand() {
        // Given
        int fid = 123;
        long lastWriteTime = System.currentTimeMillis();

        // When
        SmbComClose smbComClose = new SmbComClose(config, fid, lastWriteTime);

        // Then
        assertEquals(ServerMessageBlock.SMB_COM_CLOSE, smbComClose.getCommand());
        // Private fields are not directly accessible, but we can check their effect in other methods.
    }

    @Test
    @DisplayName("Verify writeParameterWordsWireFormat writes FID correctly")
    public void shouldWriteFidCorrectly() {
        // Given
        int fid = 456;
        long lastWriteTime = System.currentTimeMillis();
        SmbComClose smbComClose = new SmbComClose(config, fid, lastWriteTime);
        byte[] dst = new byte[6];

        // When
        int bytesWritten = smbComClose.writeParameterWordsWireFormat(dst, 0);

        // Then
        assertEquals(6, bytesWritten);
        assertEquals(fid, SMBUtil.readInt2(dst, 0));
        // lastWriteTime is not written if digest is null, so the remaining bytes should be zero
        assertEquals(0, SMBUtil.readInt4(dst, 2));
    }

    @Test
    @DisplayName("Verify writeParameterWordsWireFormat handles signing digest correctly")
    public void shouldHandleSigningDigestCorrectly() {
        // Given
        int fid = 789;
        long lastWriteTime = System.currentTimeMillis();
        SmbComClose smbComClose = new SmbComClose(config, fid, lastWriteTime);
        smbComClose.setDigest(mock(SMB1SigningDigest.class));
        byte[] dst = new byte[6];

        // When
        int bytesWritten = smbComClose.writeParameterWordsWireFormat(dst, 0);

        // Then
        assertEquals(6, bytesWritten);
        assertEquals(fid, SMBUtil.readInt2(dst, 0));
        // With a digest, the lastWriteTime should be written.
        // We can't verify the exact bytes without a real implementation of writeUTime,
        // but we can check that it's not zero.
        long writtenTime = SMBUtil.readInt4(dst, 2) & 0xFFFFFFFFL;
        // This is a weak check, but better than nothing.
        // A more robust test would require a real SMB1SigningDigest.
        assertTrue(writtenTime != 0 || lastWriteTime == 0);
    }

    @Test
    @DisplayName("Verify writeBytesWireFormat returns zero bytes written")
    public void shouldReturnZeroBytesWritten() {
        // Given
        SmbComClose smbComClose = new SmbComClose(config, 1, 1L);
        byte[] dst = new byte[0];

        // When
        int bytesWritten = smbComClose.writeBytesWireFormat(dst, 0);

        // Then
        assertEquals(0, bytesWritten);
    }

    @Test
    @DisplayName("Verify readParameterWordsWireFormat returns zero bytes read")
    public void shouldReturnZeroBytesReadFromParameters() {
        // Given
        SmbComClose smbComClose = new SmbComClose(config, 1, 1L);
        byte[] buffer = new byte[0];

        // When
        int bytesRead = smbComClose.readParameterWordsWireFormat(buffer, 0);

        // Then
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("Verify readBytesWireFormat returns zero bytes read")
    public void shouldReturnZeroBytesReadFromBytes() {
        // Given
        SmbComClose smbComClose = new SmbComClose(config, 1, 1L);
        byte[] buffer = new byte[0];

        // When
        int bytesRead = smbComClose.readBytesWireFormat(buffer, 0);

        // Then
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("Verify toString returns formatted string with FID and lastWriteTime")
    public void shouldReturnFormattedString() {
        // Given
        int fid = 999;
        long lastWriteTime = 1672531200000L; // 2023-01-01 00:00:00 UTC
        SmbComClose smbComClose = new SmbComClose(config, fid, lastWriteTime);

        // When
        String result = smbComClose.toString();

        // Then
        assertTrue(result.startsWith("SmbComClose["));
        assertTrue(result.contains("fid=" + fid));
        assertTrue(result.contains("lastWriteTime=" + lastWriteTime));
        assertTrue(result.endsWith("]"));
    }

    @Test
    @DisplayName("Verify getResponse returns the set response object")
    public void shouldReturnSetResponseObject() {
        // Given
        SmbComClose smbComClose = new SmbComClose(config, 1, 1L);
        SmbComBlankResponse expectedResponse = new SmbComBlankResponse(config);
        smbComClose.setResponse(expectedResponse);

        // When
        SmbComBlankResponse actualResponse = smbComClose.getResponse();

        // Then
        assertEquals(expectedResponse, actualResponse);
    }

    @Test
    @DisplayName("Verify initResponse creates and sets new blank response")
    public void shouldCreateAndSetNewBlankResponse() {
        // Given
        SmbComClose smbComClose = new SmbComClose(config, 1, 1L);

        // When
        SmbComBlankResponse response = smbComClose.initResponse(context);

        // Then
        assertNotNull(response);
        assertEquals(response, smbComClose.getResponse());
    }
}
