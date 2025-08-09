package jcifs.internal.smb2.tree;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.lenient;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jcifs.BaseTest;
import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for Smb2TreeConnectRequest functionality
 */
@DisplayName("Smb2TreeConnectRequest Tests")
@MockitoSettings(strictness = Strictness.LENIENT)
class Smb2TreeConnectRequestTest extends BaseTest {

    private Configuration mockConfig;
    private CIFSContext mockContext;
    private Smb2TreeConnectRequest request;
    private static final String TEST_PATH = "\\\\server\\share";

    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
        mockContext = mock(CIFSContext.class);
        when(mockContext.getConfig()).thenReturn(mockConfig);
        request = new Smb2TreeConnectRequest(mockConfig, TEST_PATH);
    }

    @Test
    @DisplayName("Should create request with correct command type and path")
    void testConstructorSetsCorrectCommandAndPath() throws Exception {
        // Given & When
        String path = "\\\\testserver\\testshare";
        Smb2TreeConnectRequest req = new Smb2TreeConnectRequest(mockConfig, path);

        // Then - verify command is set correctly using reflection
        Field commandField = ServerMessageBlock2.class.getDeclaredField("command");
        commandField.setAccessible(true);
        int command = (int) commandField.get(req);
        
        assertEquals(0x0003, command); // SMB2_TREE_CONNECT command value
        
        // Verify path is set correctly
        Field pathField = Smb2TreeConnectRequest.class.getDeclaredField("path");
        pathField.setAccessible(true);
        String actualPath = (String) pathField.get(req);
        assertEquals(path, actualPath);
    }

    @Test
    @DisplayName("Should create proper response object")
    void testCreateResponse() {
        // When
        Smb2TreeConnectResponse response = request.createResponse(mockContext, request);

        // Then
        assertNotNull(response);
        assertTrue(response instanceof Smb2TreeConnectResponse);
        verify(mockContext, times(1)).getConfig();
    }

    @Test
    @DisplayName("Should calculate correct message size for different paths")
    void testSize() {
        // Given
        String shortPath = "\\\\a\\b";
        String longPath = "\\\\server.domain.com\\very_long_share_name_here";
        
        Smb2TreeConnectRequest shortReq = new Smb2TreeConnectRequest(mockConfig, shortPath);
        Smb2TreeConnectRequest longReq = new Smb2TreeConnectRequest(mockConfig, longPath);

        // When
        int shortSize = shortReq.size();
        int longSize = longReq.size();

        // Then
        // SMB2_HEADER_LENGTH + 8 + path.length() * 2 (UTF-16LE)
        int expectedShortSize = Smb2Constants.SMB2_HEADER_LENGTH + 8 + shortPath.length() * 2;
        int expectedLongSize = Smb2Constants.SMB2_HEADER_LENGTH + 8 + longPath.length() * 2;
        
        // size8 method aligns to 8-byte boundary
        int alignedShortSize = (expectedShortSize + 7) & ~7;
        int alignedLongSize = (expectedLongSize + 7) & ~7;
        
        assertEquals(alignedShortSize, shortSize);
        assertEquals(alignedLongSize, longSize);
    }

    @Test
    @DisplayName("Should write correct bytes to wire format")
    void testWriteBytesWireFormat() throws Exception {
        // Given
        byte[] buffer = new byte[512];
        int headerStart = 50;
        int bodyOffset = headerStart + Smb2Constants.SMB2_HEADER_LENGTH;
        
        // Encode the full message to set headerStart
        request.encode(buffer, headerStart);

        // Then - verify the body was written correctly
        byte[] pathBytes = TEST_PATH.getBytes(StandardCharsets.UTF_16LE);
        
        // Verify structure size (9)
        assertEquals(9, SMBUtil.readInt2(buffer, bodyOffset));
        
        // Verify tree flags (0)
        assertEquals(0, SMBUtil.readInt2(buffer, bodyOffset + 2));
        
        // Verify path offset (points to after the 8-byte structure)
        int expectedPathOffset = bodyOffset + 8 - headerStart;
        assertEquals(expectedPathOffset, SMBUtil.readInt2(buffer, bodyOffset + 4));
        
        // Verify path length
        assertEquals(pathBytes.length, SMBUtil.readInt2(buffer, bodyOffset + 6));
        
        // Verify path content
        byte[] actualPath = new byte[pathBytes.length];
        System.arraycopy(buffer, bodyOffset + 8, actualPath, 0, pathBytes.length);
        assertArrayEquals(pathBytes, actualPath);
    }

    @Test
    @DisplayName("Should handle chain operation correctly")
    void testChain() {
        // Given
        ServerMessageBlock2 nextMessage = mock(ServerMessageBlock2.class);
        
        // When
        boolean result = request.chain(nextMessage);
        
        // Then
        verify(nextMessage).setTreeId(Smb2Constants.UNSPECIFIED_TREEID);
        assertTrue(result); // Assuming superclass chain returns true
    }

    @Test
    @DisplayName("Should always return 0 for readBytesWireFormat")
    void testReadBytesWireFormat() {
        // Given
        byte[] buffer = createTestData(256);
        
        // When
        int bytesRead = request.readBytesWireFormat(buffer, 0);
        
        // Then
        assertEquals(0, bytesRead);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "\\\\server\\share",
        "\\\\192.168.1.1\\share",
        "\\\\server.domain.com\\share",
        "\\\\server\\share\\subfolder",
        "\\\\s\\s" // Minimum path
    })
    @DisplayName("Should handle various valid path formats")
    void testVariousPathFormats(String path) throws Exception {
        // Given
        Smb2TreeConnectRequest req = new Smb2TreeConnectRequest(mockConfig, path);
        byte[] buffer = new byte[1024];
        
        // Encode to set headerStart
        req.encode(buffer, 0);

        // Then
        byte[] pathBytes = path.getBytes(StandardCharsets.UTF_16LE);
        
        // Verify path is written correctly at body + 8
        byte[] actualPath = new byte[pathBytes.length];
        System.arraycopy(buffer, Smb2Constants.SMB2_HEADER_LENGTH + 8, actualPath, 0, pathBytes.length);
        assertArrayEquals(pathBytes, actualPath);
    }

    @Test
    @DisplayName("Should handle Unicode characters in path")
    void testUnicodePathHandling() throws Exception {
        // Given
        String unicodePath = "\\\\server\\共享文件夹\\テスト";
        Smb2TreeConnectRequest req = new Smb2TreeConnectRequest(mockConfig, unicodePath);
        byte[] buffer = new byte[1024];
        
        // Encode to set headerStart
        req.encode(buffer, 0);

        // Then
        byte[] pathBytes = unicodePath.getBytes(StandardCharsets.UTF_16LE);
        
        // Verify Unicode path is preserved
        byte[] actualPath = new byte[pathBytes.length];
        System.arraycopy(buffer, Smb2Constants.SMB2_HEADER_LENGTH + 8, actualPath, 0, pathBytes.length);
        assertArrayEquals(pathBytes, actualPath);
    }

    @Test
    @DisplayName("Should handle empty path")
    void testEmptyPath() throws Exception {
        // Given
        String emptyPath = "";
        Smb2TreeConnectRequest req = new Smb2TreeConnectRequest(mockConfig, emptyPath);
        byte[] buffer = new byte[256];
        
        // When
        req.encode(buffer, 0);
        
        // Then
        assertEquals(0, SMBUtil.readInt2(buffer, Smb2Constants.SMB2_HEADER_LENGTH + 6)); // Path length should be 0
    }

    @Test
    @DisplayName("Should handle null path")
    void testNullPath() {
        // When creating with null path
        Smb2TreeConnectRequest reqWithNull = new Smb2TreeConnectRequest(mockConfig, null);
        
        // Then - should not throw during construction
        assertNotNull(reqWithNull);
        
        // But should throw when trying to use the null path
        assertThrows(NullPointerException.class, () -> {
            reqWithNull.size();
        });
    }

    @Test
    @DisplayName("Should write consistent structure at different offsets")
    void testWriteBytesAtDifferentOffsets() throws Exception {
        // Test at different offsets
        int[] offsets = {0, 10, 50, 100, 200};
        
        for (int offset : offsets) {
            // Given
            byte[] buffer = new byte[1024];
            Smb2TreeConnectRequest req = new Smb2TreeConnectRequest(mockConfig, TEST_PATH);
            
            // When
            req.encode(buffer, offset);
            
            // Then
            byte[] pathBytes = TEST_PATH.getBytes(StandardCharsets.UTF_16LE);
            int bodyOffset = offset + Smb2Constants.SMB2_HEADER_LENGTH;
            assertEquals(9, SMBUtil.readInt2(buffer, bodyOffset)); // Structure size
            assertEquals(pathBytes.length, SMBUtil.readInt2(buffer, bodyOffset + 6)); // Path length
        }
    }

    @Test
    @DisplayName("Should correctly calculate path offset from header start")
    void testPathOffsetCalculation() throws Exception {
        // Given
        byte[] buffer = new byte[512];
        int headerStart = 64;
        
        // When
        request.encode(buffer, headerStart);
        
        // Then
        int bodyOffset = headerStart + Smb2Constants.SMB2_HEADER_LENGTH;
        // Path offset should be relative to headerStart
        int pathOffset = SMBUtil.readInt2(buffer, bodyOffset + 4);
        int expectedOffset = Smb2Constants.SMB2_HEADER_LENGTH + 8;
        assertEquals(expectedOffset, pathOffset);
    }

    @Test
    @DisplayName("Should verify tree flags field")
    void testTreeFlagsField() throws Exception {
        // Given - Access treeFlags field via reflection
        Field treeFlagsField = Smb2TreeConnectRequest.class.getDeclaredField("treeFlags");
        treeFlagsField.setAccessible(true);
        
        // When - Create new request
        Smb2TreeConnectRequest req = new Smb2TreeConnectRequest(mockConfig, TEST_PATH);
        
        // Then - Tree flags should be initialized to 0
        int flags = (int) treeFlagsField.get(req);
        assertEquals(0, flags);
    }

    @Test
    @DisplayName("Should handle maximum path length")
    void testMaximumPathLength() throws Exception {
        // Given - Create a very long path
        StringBuilder longPathBuilder = new StringBuilder("\\\\server\\");
        for (int i = 0; i < 1000; i++) {
            longPathBuilder.append("a");
        }
        String longPath = longPathBuilder.toString();
        
        Smb2TreeConnectRequest req = new Smb2TreeConnectRequest(mockConfig, longPath);
        byte[] buffer = new byte[4096];
        
        // When
        req.encode(buffer, 0);
        
        // Then
        byte[] pathBytes = longPath.getBytes(StandardCharsets.UTF_16LE);
        assertEquals(pathBytes.length, SMBUtil.readInt2(buffer, Smb2Constants.SMB2_HEADER_LENGTH + 6));
    }

    @Test
    @DisplayName("Should throw exception when buffer too small for path")
    void testBufferTooSmallForPath() throws Exception {
        // Given
        String longPath = "\\\\server\\very_long_share_name_that_exceeds_buffer";
        Smb2TreeConnectRequest req = new Smb2TreeConnectRequest(mockConfig, longPath);
        byte[] smallBuffer = new byte[20]; // Too small for header + path
        
        // When & Then
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            req.encode(smallBuffer, 0);
        });
    }

    @Test
    @DisplayName("Should correctly inherit from ServerMessageBlock2Request")
    void testInheritance() {
        // Then
        assertTrue(request instanceof ServerMessageBlock2Request);
        assertTrue(request instanceof ServerMessageBlock2);
    }

    @Test
    @DisplayName("Should maintain immutability of structure size")
    void testStructureSizeImmutability() throws Exception {
        // Given
        byte[] buffer = new byte[2048];
        
        // When - encode at multiple positions
        for (int i = 0; i < 5; i++) {
            Smb2TreeConnectRequest req = new Smb2TreeConnectRequest(mockConfig, TEST_PATH);
            req.encode(buffer, i * 200);
        }
        
        // Then - all should have same structure size (9)
        for (int i = 0; i < 5; i++) {
            int bodyOffset = (i * 200) + Smb2Constants.SMB2_HEADER_LENGTH;
            assertEquals(9, SMBUtil.readInt2(buffer, bodyOffset));
        }
    }

    @Test
    @DisplayName("Should handle path with special characters")
    void testSpecialCharactersInPath() throws Exception {
        // Given
        String specialPath = "\\\\server\\share$\\folder@123\\file#test";
        Smb2TreeConnectRequest req = new Smb2TreeConnectRequest(mockConfig, specialPath);
        byte[] buffer = new byte[512];
        
        // When
        req.encode(buffer, 0);
        
        // Then
        byte[] pathBytes = specialPath.getBytes(StandardCharsets.UTF_16LE);
        
        // Verify special characters are preserved
        byte[] actualPath = new byte[pathBytes.length];
        System.arraycopy(buffer, Smb2Constants.SMB2_HEADER_LENGTH + 8, actualPath, 0, pathBytes.length);
        assertArrayEquals(pathBytes, actualPath);
    }

    @Test
    @DisplayName("Should verify size8 alignment calculation")
    void testSize8Alignment() throws Exception {
        // Given - Various path lengths to test alignment
        String[] paths = {
            "\\\\a\\b",           // Short path
            "\\\\server\\share",  // Medium path
            "\\\\server.domain.com\\longshare" // Long path
        };
        
        Method size8Method = ServerMessageBlock2.class.getDeclaredMethod("size8", int.class);
        size8Method.setAccessible(true);
        
        for (String path : paths) {
            Smb2TreeConnectRequest req = new Smb2TreeConnectRequest(mockConfig, path);
            
            // When
            int actualSize = req.size();
            int expectedUnaligned = Smb2Constants.SMB2_HEADER_LENGTH + 8 + path.length() * 2;
            int expectedAligned = (int) size8Method.invoke(req, expectedUnaligned);
            
            // Then
            assertEquals(expectedAligned, actualSize);
            assertEquals(0, actualSize % 8); // Should be 8-byte aligned
        }
    }

    @Test
    @DisplayName("Should write proper wire format structure")
    void testWireFormatStructure() throws Exception {
        // Given
        String simplePath = "\\\\S\\s"; // Simple path for easier verification
        Smb2TreeConnectRequest req = new Smb2TreeConnectRequest(mockConfig, simplePath);
        byte[] buffer = new byte[256];
        
        // When
        req.encode(buffer, 0);
        
        // Then
        byte[] pathBytes = simplePath.getBytes(StandardCharsets.UTF_16LE);
        int bodyOffset = Smb2Constants.SMB2_HEADER_LENGTH;
        
        // Verify complete structure
        assertEquals(9, SMBUtil.readInt2(buffer, bodyOffset));        // Structure size
        assertEquals(0, SMBUtil.readInt2(buffer, bodyOffset + 2));        // Tree flags
        assertEquals(Smb2Constants.SMB2_HEADER_LENGTH + 8, SMBUtil.readInt2(buffer, bodyOffset + 4)); // Path offset
        assertEquals(pathBytes.length, SMBUtil.readInt2(buffer, bodyOffset + 6)); // Path length
        
        // Verify path content
        byte[] actualPath = new byte[pathBytes.length];
        System.arraycopy(buffer, bodyOffset + 8, actualPath, 0, pathBytes.length);
        assertArrayEquals(pathBytes, actualPath);
    }

    @Test
    @DisplayName("Should handle response creation with null config from context")
    void testCreateResponseWithNullConfigFromContext() {
        // Given
        CIFSContext nullConfigContext = mock(CIFSContext.class);
        when(nullConfigContext.getConfig()).thenReturn(null);
        
        // When
        Smb2TreeConnectResponse response = request.createResponse(nullConfigContext, request);
        
        // Then - should create response but with null config
        assertNotNull(response);
        assertTrue(response instanceof Smb2TreeConnectResponse);
    }

    @Test
    @DisplayName("Should verify proper UTF-16LE encoding")
    void testUtf16LeEncoding() throws Exception {
        // Given - Path with various characters
        String testPath = "\\\\server\\test123";
        Smb2TreeConnectRequest req = new Smb2TreeConnectRequest(mockConfig, testPath);
        byte[] buffer = new byte[512];
        
        // When
        req.encode(buffer, 0);
        
        // Then - Verify UTF-16LE encoding
        byte[] expectedBytes = testPath.getBytes(StandardCharsets.UTF_16LE);
        byte[] actualBytes = new byte[expectedBytes.length];
        System.arraycopy(buffer, Smb2Constants.SMB2_HEADER_LENGTH + 8, actualBytes, 0, expectedBytes.length);
        
        assertArrayEquals(expectedBytes, actualBytes);
        
        // Verify it's actually UTF-16LE (each ASCII char should be followed by 0x00)
        int pathStart = Smb2Constants.SMB2_HEADER_LENGTH + 8;
        for (int i = 0; i < testPath.length(); i++) {
            char c = testPath.charAt(i);
            if (c < 128) { // ASCII character
                assertEquals(c, buffer[pathStart + i * 2]);
                assertEquals(0, buffer[pathStart + i * 2 + 1]);
            }
        }
    }

    @Test
    @DisplayName("Should test writeBytesWireFormat directly")
    void testWriteBytesWireFormatDirect() {
        // Given
        byte[] buffer = new byte[512];
        int offset = 100;
        
        // First encode to set headerStart
        byte[] tempBuffer = new byte[512];
        request.encode(tempBuffer, 50);
        
        // When
        int bytesWritten = request.writeBytesWireFormat(buffer, offset);
        
        // Then
        byte[] pathBytes = TEST_PATH.getBytes(StandardCharsets.UTF_16LE);
        int expectedBytesWritten = 8 + pathBytes.length;
        assertEquals(expectedBytesWritten, bytesWritten);
        
        // Verify structure size (9)
        assertEquals(9, SMBUtil.readInt2(buffer, offset));
        
        // Verify tree flags (0)
        assertEquals(0, SMBUtil.readInt2(buffer, offset + 2));
        
        // Verify path length
        assertEquals(pathBytes.length, SMBUtil.readInt2(buffer, offset + 6));
        
        // Verify path content
        byte[] actualPath = new byte[pathBytes.length];
        System.arraycopy(buffer, offset + 8, actualPath, 0, pathBytes.length);
        assertArrayEquals(pathBytes, actualPath);
    }
}