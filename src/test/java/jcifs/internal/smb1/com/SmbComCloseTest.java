package jcifs.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.config.PropertyConfiguration;
import jcifs.internal.smb1.SMB1SigningDigest;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.util.SMBUtil;

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

    /**
     * Test method for {@link jcifs.internal.smb1.com.SmbComClose#SmbComClose(jcifs.Configuration, int, long)}.
     */
    @Test
    public void testConstructor() {
        // Given
        int fid = 123;
        long lastWriteTime = System.currentTimeMillis();

        // When
        SmbComClose smbComClose = new SmbComClose(config, fid, lastWriteTime);

        // Then
        assertEquals(ServerMessageBlock.SMB_COM_CLOSE, smbComClose.getCommand());
        // Private fields are not directly accessible, but we can check their effect in other methods.
    }

    /**
     * Test method for {@link jcifs.internal.smb1.com.SmbComClose#writeParameterWordsWireFormat(byte[], int)}.
     */
    @Test
    public void testWriteParameterWordsWireFormat() {
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

    /**
     * Test method for {@link jcifs.internal.smb1.com.SmbComClose#writeParameterWordsWireFormat(byte[], int)} with a signing digest.
     */
    @Test
    public void testWriteParameterWordsWireFormatWithDigest() {
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

    /**
     * Test method for {@link jcifs.internal.smb1.com.SmbComClose#writeBytesWireFormat(byte[], int)}.
     */
    @Test
    public void testWriteBytesWireFormat() {
        // Given
        SmbComClose smbComClose = new SmbComClose(config, 1, 1L);
        byte[] dst = new byte[0];

        // When
        int bytesWritten = smbComClose.writeBytesWireFormat(dst, 0);

        // Then
        assertEquals(0, bytesWritten);
    }

    /**
     * Test method for {@link jcifs.internal.smb1.com.SmbComClose#readParameterWordsWireFormat(byte[], int)}.
     */
    @Test
    public void testReadParameterWordsWireFormat() {
        // Given
        SmbComClose smbComClose = new SmbComClose(config, 1, 1L);
        byte[] buffer = new byte[0];

        // When
        int bytesRead = smbComClose.readParameterWordsWireFormat(buffer, 0);

        // Then
        assertEquals(0, bytesRead);
    }

    /**
     * Test method for {@link jcifs.internal.smb1.com.SmbComClose#readBytesWireFormat(byte[], int)}.
     */
    @Test
    public void testReadBytesWireFormat() {
        // Given
        SmbComClose smbComClose = new SmbComClose(config, 1, 1L);
        byte[] buffer = new byte[0];

        // When
        int bytesRead = smbComClose.readBytesWireFormat(buffer, 0);

        // Then
        assertEquals(0, bytesRead);
    }

    /**
     * Test method for {@link jcifs.internal.smb1.com.SmbComClose#toString()}.
     */
    @Test
    public void testToString() {
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

    /**
     * Test method for {@link jcifs.internal.smb1.com.SmbComClose#getResponse()}.
     */
    @Test
    public void testGetResponse() {
        // Given
        SmbComClose smbComClose = new SmbComClose(config, 1, 1L);
        SmbComBlankResponse expectedResponse = new SmbComBlankResponse(config);
        smbComClose.setResponse(expectedResponse);

        // When
        SmbComBlankResponse actualResponse = smbComClose.getResponse();

        // Then
        assertEquals(expectedResponse, actualResponse);
    }

    /**
     * Test method for {@link jcifs.internal.smb1.com.SmbComClose#initResponse(jcifs.CIFSContext)}.
     */
    @Test
    public void testInitResponse() {
        // Given
        SmbComClose smbComClose = new SmbComClose(config, 1, 1L);

        // When
        SmbComBlankResponse response = smbComClose.initResponse(context);

        // Then
        assertNotNull(response);
        assertEquals(response, smbComClose.getResponse());
    }
}
