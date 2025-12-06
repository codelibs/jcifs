package org.codelibs.jcifs.smb.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link SmbComDeleteDirectory} class.
 */
@DisplayName("SmbComDeleteDirectory Tests")
public class SmbComDeleteDirectoryTest {

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
        String path = "test\\directory";

        // When
        SmbComDeleteDirectory deleteDir = new SmbComDeleteDirectory(config, path);

        // Then
        assertEquals(ServerMessageBlock.SMB_COM_DELETE_DIRECTORY, deleteDir.getCommand());
    }

    @Test
    @DisplayName("writeParameterWordsWireFormat writes nothing")
    public void shouldWriteNoParameterWords() {
        // Given
        String path = "test\\directory";
        SmbComDeleteDirectory deleteDir = new SmbComDeleteDirectory(config, path);
        byte[] dst = new byte[10];

        // When
        int bytesWritten = deleteDir.writeParameterWordsWireFormat(dst, 0);

        // Then
        assertEquals(0, bytesWritten);
    }

    @Test
    @DisplayName("writeBytesWireFormat writes path correctly")
    public void shouldWritePathCorrectly() {
        // Given
        String path = "test\\directory";
        SmbComDeleteDirectory deleteDir = new SmbComDeleteDirectory(config, path);
        byte[] dst = new byte[100];

        // When
        int bytesWritten = deleteDir.writeBytesWireFormat(dst, 0);

        // Then
        assertTrue(bytesWritten > 0);
        assertEquals(0x04, dst[0]); // Buffer format indicator
    }

    @Test
    @DisplayName("writeBytesWireFormat with empty path")
    public void shouldHandleEmptyPath() {
        // Given
        String path = "";
        SmbComDeleteDirectory deleteDir = new SmbComDeleteDirectory(config, path);
        byte[] dst = new byte[100];

        // When
        int bytesWritten = deleteDir.writeBytesWireFormat(dst, 0);

        // Then
        assertTrue(bytesWritten > 0);
        assertEquals(0x04, dst[0]);
    }

    @Test
    @DisplayName("writeBytesWireFormat with nested directory path")
    public void shouldHandleNestedPath() {
        // Given
        String path = "parent\\child\\grandchild";
        SmbComDeleteDirectory deleteDir = new SmbComDeleteDirectory(config, path);
        byte[] dst = new byte[200];

        // When
        int bytesWritten = deleteDir.writeBytesWireFormat(dst, 0);

        // Then
        assertTrue(bytesWritten > path.length());
        assertEquals(0x04, dst[0]);
    }

    @Test
    @DisplayName("readParameterWordsWireFormat returns zero")
    public void shouldReturnZeroForReadParameterWords() {
        // Given
        String path = "test\\directory";
        SmbComDeleteDirectory deleteDir = new SmbComDeleteDirectory(config, path);
        byte[] buffer = new byte[10];

        // When
        int bytesRead = deleteDir.readParameterWordsWireFormat(buffer, 0);

        // Then
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("readBytesWireFormat returns zero")
    public void shouldReturnZeroForReadBytes() {
        // Given
        String path = "test\\directory";
        SmbComDeleteDirectory deleteDir = new SmbComDeleteDirectory(config, path);
        byte[] buffer = new byte[10];

        // When
        int bytesRead = deleteDir.readBytesWireFormat(buffer, 0);

        // Then
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("toString contains directory path")
    public void shouldIncludeDirectoryPathInToString() {
        // Given
        String path = "test\\directory";
        SmbComDeleteDirectory deleteDir = new SmbComDeleteDirectory(config, path);

        // When
        String result = deleteDir.toString();

        // Then
        assertNotNull(result);
        assertTrue(result.contains("SmbComDeleteDirectory"));
        assertTrue(result.contains(path));
        assertTrue(result.contains("directoryName"));
    }

    @Test
    @DisplayName("Constructor with null path")
    public void shouldHandleNullPath() {
        // When & Then - should not throw during construction
        assertDoesNotThrow(() -> {
            new SmbComDeleteDirectory(config, null);
        });
    }

    @Test
    @DisplayName("Multiple delete directory commands are independent")
    public void shouldCreateIndependentInstances() {
        // Given
        String path1 = "dir1";
        String path2 = "dir2";

        // When
        SmbComDeleteDirectory deleteDir1 = new SmbComDeleteDirectory(config, path1);
        SmbComDeleteDirectory deleteDir2 = new SmbComDeleteDirectory(config, path2);

        // Then
        assertNotSame(deleteDir1, deleteDir2);
        assertTrue(deleteDir1.toString().contains(path1));
        assertTrue(deleteDir2.toString().contains(path2));
    }

    @Test
    @DisplayName("Write operations with different offsets")
    public void shouldHandleDifferentOffsets() {
        // Given
        String path = "testdir";
        SmbComDeleteDirectory deleteDir = new SmbComDeleteDirectory(config, path);
        byte[] dst = new byte[100];

        // When
        int offset1 = 0;
        int offset2 = 10;
        int bytes1 = deleteDir.writeParameterWordsWireFormat(dst, offset1);
        int bytes2 = deleteDir.writeBytesWireFormat(dst, offset2);

        // Then
        assertEquals(0, bytes1);
        assertTrue(bytes2 > 0);
        assertEquals(0x04, dst[offset2]);
    }

    @Test
    @DisplayName("Path with special characters")
    public void shouldHandleSpecialCharactersInPath() {
        // Given
        String path = "test-dir_123\\sub.dir";
        SmbComDeleteDirectory deleteDir = new SmbComDeleteDirectory(config, path);
        byte[] dst = new byte[100];

        // When
        int bytesWritten = deleteDir.writeBytesWireFormat(dst, 0);

        // Then
        assertTrue(bytesWritten > 0);
        assertEquals(0x04, dst[0]);
        assertTrue(deleteDir.toString().contains(path));
    }

    @Test
    @DisplayName("Long directory path")
    public void shouldHandleLongDirectoryPath() {
        // Given
        StringBuilder longPath = new StringBuilder();
        for (int i = 0; i < 20; i++) {
            if (i > 0)
                longPath.append("\\");
            longPath.append("dir").append(i);
        }
        SmbComDeleteDirectory deleteDir = new SmbComDeleteDirectory(config, longPath.toString());
        byte[] dst = new byte[500];

        // When
        int bytesWritten = deleteDir.writeBytesWireFormat(dst, 0);

        // Then
        assertTrue(bytesWritten > 0);
        assertEquals(0x04, dst[0]);
    }
}
