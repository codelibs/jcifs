package org.codelibs.jcifs.smb.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link SmbComDelete} class.
 */
@DisplayName("SmbComDelete Tests")
public class SmbComDeleteTest {

    private PropertyConfiguration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        Properties properties = new Properties();
        config = new PropertyConfiguration(properties);
    }

    @Test
    @DisplayName("Constructor initializes with correct command")
    public void shouldInitializeWithCorrectCommand() {
        // Given
        String path = "test\\file.txt";

        // When
        SmbComDelete delete = new SmbComDelete(config, path);

        // Then
        assertEquals(ServerMessageBlock.SMB_COM_DELETE, delete.getCommand());
    }

    @Test
    @DisplayName("writeParameterWordsWireFormat writes search attributes")
    public void shouldWriteSearchAttributes() {
        // Given
        String path = "test\\file.txt";
        SmbComDelete delete = new SmbComDelete(config, path);
        byte[] dst = new byte[10];

        // When
        int bytesWritten = delete.writeParameterWordsWireFormat(dst, 0);

        // Then
        assertEquals(2, bytesWritten);
        int attributes = SMBUtil.readInt2(dst, 0);
        // Should include HIDDEN and SYSTEM attributes
        assertTrue((attributes & SmbConstants.ATTR_HIDDEN) != 0);
        assertTrue((attributes & SmbConstants.ATTR_SYSTEM) != 0);
    }

    @Test
    @DisplayName("writeBytesWireFormat writes path correctly")
    public void shouldWritePathCorrectly() {
        // Given
        String path = "test\\file.txt";
        SmbComDelete delete = new SmbComDelete(config, path);
        byte[] dst = new byte[100];

        // When
        int bytesWritten = delete.writeBytesWireFormat(dst, 0);

        // Then
        assertTrue(bytesWritten > 0);
        assertEquals(0x04, dst[0]); // Buffer format indicator
    }

    @Test
    @DisplayName("writeBytesWireFormat with empty path")
    public void shouldHandleEmptyPath() {
        // Given
        String path = "";
        SmbComDelete delete = new SmbComDelete(config, path);
        byte[] dst = new byte[100];

        // When
        int bytesWritten = delete.writeBytesWireFormat(dst, 0);

        // Then
        assertTrue(bytesWritten > 0);
        assertEquals(0x04, dst[0]);
    }

    @Test
    @DisplayName("writeBytesWireFormat with long path")
    public void shouldHandleLongPath() {
        // Given
        String path = "very\\long\\path\\to\\some\\deeply\\nested\\directory\\structure\\file.txt";
        SmbComDelete delete = new SmbComDelete(config, path);
        byte[] dst = new byte[200];

        // When
        int bytesWritten = delete.writeBytesWireFormat(dst, 0);

        // Then
        assertTrue(bytesWritten > path.length());
        assertEquals(0x04, dst[0]);
    }

    @Test
    @DisplayName("readParameterWordsWireFormat returns zero")
    public void shouldReturnZeroForReadParameterWords() {
        // Given
        String path = "test\\file.txt";
        SmbComDelete delete = new SmbComDelete(config, path);
        byte[] buffer = new byte[10];

        // When
        int bytesRead = delete.readParameterWordsWireFormat(buffer, 0);

        // Then
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("readBytesWireFormat returns zero")
    public void shouldReturnZeroForReadBytes() {
        // Given
        String path = "test\\file.txt";
        SmbComDelete delete = new SmbComDelete(config, path);
        byte[] buffer = new byte[10];

        // When
        int bytesRead = delete.readBytesWireFormat(buffer, 0);

        // Then
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("toString contains path and attributes")
    public void shouldIncludePathInToString() {
        // Given
        String path = "test\\file.txt";
        SmbComDelete delete = new SmbComDelete(config, path);

        // When
        String result = delete.toString();

        // Then
        assertNotNull(result);
        assertTrue(result.contains("SmbComDelete"));
        assertTrue(result.contains(path));
        assertTrue(result.contains("searchAttributes"));
    }

    @Test
    @DisplayName("Constructor with null path")
    public void shouldHandleNullPath() {
        // When & Then - should not throw during construction
        assertDoesNotThrow(() -> {
            new SmbComDelete(config, null);
        });
    }

    @Test
    @DisplayName("Multiple delete commands are independent")
    public void shouldCreateIndependentInstances() {
        // Given
        String path1 = "file1.txt";
        String path2 = "file2.txt";

        // When
        SmbComDelete delete1 = new SmbComDelete(config, path1);
        SmbComDelete delete2 = new SmbComDelete(config, path2);

        // Then
        assertNotSame(delete1, delete2);
        assertTrue(delete1.toString().contains(path1));
        assertTrue(delete2.toString().contains(path2));
    }

    @Test
    @DisplayName("Write operations with different offsets")
    public void shouldHandleDifferentOffsets() {
        // Given
        String path = "test.txt";
        SmbComDelete delete = new SmbComDelete(config, path);
        byte[] dst = new byte[100];

        // When
        int offset1 = 0;
        int offset2 = 10;
        int bytes1 = delete.writeParameterWordsWireFormat(dst, offset1);
        int bytes2 = delete.writeBytesWireFormat(dst, offset2);

        // Then
        assertEquals(2, bytes1);
        assertTrue(bytes2 > 0);
        // Verify data was written at correct offsets
        assertNotEquals(0, SMBUtil.readInt2(dst, offset1));
        assertEquals(0x04, dst[offset2]);
    }
}
