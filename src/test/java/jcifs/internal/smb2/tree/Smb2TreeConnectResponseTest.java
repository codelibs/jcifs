package jcifs.internal.smb2.tree;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.any;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import jcifs.BaseTest;
import jcifs.Configuration;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.CommonServerMessageBlockResponse;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.TreeConnectResponse;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.util.SMBUtil;

import java.util.stream.Stream;

/**
 * Test class for Smb2TreeConnectResponse functionality
 */
@DisplayName("Smb2TreeConnectResponse Tests")
class Smb2TreeConnectResponseTest extends BaseTest {

    private Configuration mockConfig;
    private Smb2TreeConnectResponse response;

    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
        response = new Smb2TreeConnectResponse(mockConfig);
    }

    @Test
    @DisplayName("Should create response with configuration")
    void testConstructorWithConfiguration() {
        // Given & When
        Smb2TreeConnectResponse resp = new Smb2TreeConnectResponse(mockConfig);

        // Then
        assertNotNull(resp);
        assertTrue(resp instanceof ServerMessageBlock2Response);
        assertTrue(resp instanceof ServerMessageBlock2);
        assertTrue(resp instanceof TreeConnectResponse);
    }

    @Test
    @DisplayName("Should return correct share type constants")
    void testShareTypeConstants() {
        // Then
        assertEquals((byte) 0x1, Smb2TreeConnectResponse.SMB2_SHARE_TYPE_DISK);
        assertEquals((byte) 0x2, Smb2TreeConnectResponse.SMB2_SHARE_TYPE_PIPE);
        assertEquals((byte) 0x3, Smb2TreeConnectResponse.SMB2_SHARE_TYPE_PRINT);
    }

    @Test
    @DisplayName("Should return correct share flag constants")
    void testShareFlagConstants() {
        // Then
        assertEquals(0x0, Smb2TreeConnectResponse.SMB2_SHAREFLAG_MANUAL_CACHING);
        assertEquals(0x10, Smb2TreeConnectResponse.SMB2_SHAREFLAG_AUTO_CACHING);
        assertEquals(0x20, Smb2TreeConnectResponse.SMB2_SHAREFLAG_VDO_CACHING);
        assertEquals(0x1, Smb2TreeConnectResponse.SMB2_SHAREFLAG_DFS);
        assertEquals(0x2, Smb2TreeConnectResponse.SMB2_SHAREFLAG_DFS_ROOT);
        assertEquals(0x100, Smb2TreeConnectResponse.SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS);
        assertEquals(0x200, Smb2TreeConnectResponse.SMB2_SHAREFLAG_FORCE_SHARED_DELETE);
        assertEquals(0x400, Smb2TreeConnectResponse.SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING);
        assertEquals(0x800, Smb2TreeConnectResponse.SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM);
        assertEquals(0x1000, Smb2TreeConnectResponse.SMB2_SHAREFLAG_FORCE_LEVEL2_OPLOCK);
        assertEquals(0x2000, Smb2TreeConnectResponse.SMB2_SHAREFLAG_ENABLE_HASH_V1);
        assertEquals(0x4000, Smb2TreeConnectResponse.SMB2_SHAREFLAG_ENABLE_HASH_V2);
        assertEquals(0x8000, Smb2TreeConnectResponse.SMB2_SHAREFLAG_ENCRYPT_DATA);
    }

    @Test
    @DisplayName("Should return correct share capability constants")
    void testShareCapabilityConstants() {
        // Then
        assertEquals(0x8, Smb2TreeConnectResponse.SMB2_SHARE_CAP_DFS);
        assertEquals(0x10, Smb2TreeConnectResponse.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY);
        assertEquals(0x20, Smb2TreeConnectResponse.SMB2_SHARE_CAP_SCALEOUT);
        assertEquals(0x40, Smb2TreeConnectResponse.SMB2_SHARE_CAP_CLUSTER);
        assertEquals(0x80, Smb2TreeConnectResponse.SMB2_SHARE_CAP_ASYMMETRIC);
    }

    @Test
    @DisplayName("Should write empty bytes to wire format")
    void testWriteBytesWireFormat() {
        // Given
        byte[] buffer = new byte[256];
        int offset = 10;

        // When
        int bytesWritten = response.writeBytesWireFormat(buffer, offset);

        // Then
        assertEquals(0, bytesWritten);
    }

    @Test
    @DisplayName("Should read valid structure from wire format")
    void testReadBytesWireFormatValidStructure() throws SMBProtocolDecodingException {
        // Given
        byte[] buffer = new byte[256];
        int offset = 10;
        
        // Write valid structure (16 bytes)
        SMBUtil.writeInt2(16, buffer, offset); // Structure size
        buffer[offset + 2] = (byte) 0x01; // Share type (DISK)
        buffer[offset + 3] = 0; // Reserved
        SMBUtil.writeInt4(0x8001, buffer, offset + 4); // Share flags (DFS | ENCRYPT_DATA)
        SMBUtil.writeInt4(0x28, buffer, offset + 8); // Capabilities (DFS | SCALEOUT)
        SMBUtil.writeInt4(0x1F01FF, buffer, offset + 12); // Maximal access

        // When
        int bytesRead = response.readBytesWireFormat(buffer, offset);

        // Then
        assertEquals(16, bytesRead);
        assertEquals((byte) 0x01, response.getShareType());
        assertEquals(0x8001, response.getShareFlags());
        assertEquals(0x28, response.getCapabilities());
        assertEquals(0x1F01FF, response.getMaximalAccess());
    }

    @DisplayName("Should throw exception for invalid structure size")
    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 4, 8, 15, 17, 32, 64, 65535})
    void testReadBytesWireFormatInvalidStructureSize(int structureSize) {
        // Given
        byte[] buffer = new byte[256];
        int offset = 0;
        
        // Write invalid structure size
        SMBUtil.writeInt2(structureSize, buffer, offset);

        // When & Then
        SMBProtocolDecodingException exception = assertThrows(
            SMBProtocolDecodingException.class, 
            () -> response.readBytesWireFormat(buffer, offset)
        );
        assertEquals("Structure size is not 16", exception.getMessage());
    }

    @DisplayName("Should parse different share types correctly")
    @ParameterizedTest
    @CsvSource({
        "1, 1",   // DISK
        "2, 2",   // PIPE  
        "3, 3",   // PRINT
        "0, 0",   // Unknown
        "255, -1" // Byte overflow to signed
    })
    void testDifferentShareTypes(int shareTypeValue, int expectedValue) throws SMBProtocolDecodingException {
        // Given
        byte[] buffer = new byte[256];
        SMBUtil.writeInt2(16, buffer, 0);
        buffer[2] = (byte) shareTypeValue;
        
        // When
        response.readBytesWireFormat(buffer, 0);
        
        // Then
        assertEquals((byte) expectedValue, response.getShareType());
    }

    @Test
    @DisplayName("Should correctly identify DFS share based on flags")
    void testIsShareDfsWithFlags() throws SMBProtocolDecodingException {
        // Test with DFS flag only
        byte[] buffer = createValidResponseBuffer(0, 0x1, 0, 0);
        response.readBytesWireFormat(buffer, 0);
        assertTrue(response.isShareDfs());

        // Test with DFS_ROOT flag only
        response = new Smb2TreeConnectResponse(mockConfig);
        buffer = createValidResponseBuffer(0, 0x2, 0, 0);
        response.readBytesWireFormat(buffer, 0);
        assertTrue(response.isShareDfs());

        // Test with both DFS flags
        response = new Smb2TreeConnectResponse(mockConfig);
        buffer = createValidResponseBuffer(0, 0x3, 0, 0);
        response.readBytesWireFormat(buffer, 0);
        assertTrue(response.isShareDfs());
    }

    @Test
    @DisplayName("Should correctly identify DFS share based on capabilities")
    void testIsShareDfsWithCapabilities() throws SMBProtocolDecodingException {
        // Test with DFS capability
        byte[] buffer = createValidResponseBuffer(0, 0, 0x8, 0);
        response.readBytesWireFormat(buffer, 0);
        assertTrue(response.isShareDfs());

        // Test without DFS flags or capabilities
        response = new Smb2TreeConnectResponse(mockConfig);
        buffer = createValidResponseBuffer(0, 0x100, 0x10, 0);
        response.readBytesWireFormat(buffer, 0);
        assertFalse(response.isShareDfs());
    }

    @Test
    @DisplayName("Should return correct TID from TreeConnectResponse interface")
    void testGetTid() throws Exception {
        // Given - set tree ID using reflection
        Method setTreeIdMethod = ServerMessageBlock2.class.getDeclaredMethod("setTreeId", int.class);
        setTreeIdMethod.setAccessible(true);
        setTreeIdMethod.invoke(response, 12345);

        // When
        int tid = response.getTid();

        // Then
        assertEquals(12345, tid);
    }

    @Test
    @DisplayName("Should validate TID correctly")
    void testIsValidTid() throws Exception {
        // Test invalid TID (-1)
        Method setTreeIdMethod = ServerMessageBlock2.class.getDeclaredMethod("setTreeId", int.class);
        setTreeIdMethod.setAccessible(true);
        setTreeIdMethod.invoke(response, -1);
        assertFalse(response.isValidTid());

        // Test valid TID
        setTreeIdMethod.invoke(response, 100);
        assertTrue(response.isValidTid());

        // Test zero TID (valid)
        setTreeIdMethod.invoke(response, 0);
        assertTrue(response.isValidTid());
    }

    @Test
    @DisplayName("Should return null for getService")
    void testGetService() {
        // When
        String service = response.getService();

        // Then
        assertNull(service);
    }

    @Test
    @DisplayName("Should prepare next request correctly when received")
    void testPrepareWhenReceived() throws Exception {
        // Given
        ServerMessageBlock2Request mockNext = mock(ServerMessageBlock2Request.class);
        
        // Set response as received using reflection
        Method setReceivedMethod = ServerMessageBlock2Response.class.getDeclaredMethod("received");
        setReceivedMethod.setAccessible(true);
        setReceivedMethod.invoke(response);
        
        // Set tree ID
        Method setTreeIdMethod = ServerMessageBlock2.class.getDeclaredMethod("setTreeId", int.class);
        setTreeIdMethod.setAccessible(true);
        setTreeIdMethod.invoke(response, 999);

        // When
        response.prepare(mockNext);

        // Then
        verify(mockNext).setTreeId(999);
    }

    @Test
    @DisplayName("Should not set tree ID when not received")
    void testPrepareWhenNotReceived() {
        // Given
        ServerMessageBlock2Request mockNext = mock(ServerMessageBlock2Request.class);

        // When
        response.prepare(mockNext);

        // Then
        verify(mockNext, times(0)).setTreeId(any(Integer.class));
    }

    @DisplayName("Should handle various share flag combinations")
    @ParameterizedTest
    @MethodSource("provideFlagCombinations")
    void testShareFlagCombinations(int flags, boolean expectedDfs) throws SMBProtocolDecodingException {
        // Given
        byte[] buffer = createValidResponseBuffer(0, flags, 0, 0);
        
        // When
        response.readBytesWireFormat(buffer, 0);
        
        // Then
        assertEquals(flags, response.getShareFlags());
        assertEquals(expectedDfs, response.isShareDfs());
    }

    private static Stream<Arguments> provideFlagCombinations() {
        return Stream.of(
            Arguments.of(0x0, false),
            Arguments.of(0x1, true),  // DFS
            Arguments.of(0x2, true),  // DFS_ROOT
            Arguments.of(0x3, true),  // DFS | DFS_ROOT
            Arguments.of(0x8000, false), // ENCRYPT_DATA only
            Arguments.of(0x8001, true),  // ENCRYPT_DATA | DFS
            Arguments.of(0xFFFF, true)   // All flags including DFS
        );
    }

    @Test
    @DisplayName("Should handle maximum values for all fields")
    void testMaximumValues() throws SMBProtocolDecodingException {
        // Given
        byte[] buffer = new byte[256];
        SMBUtil.writeInt2(16, buffer, 0);
        buffer[2] = (byte) 0xFF; // Max share type
        buffer[3] = 0;
        SMBUtil.writeInt4(0xFFFFFFFF, buffer, 4); // Max share flags
        SMBUtil.writeInt4(0xFFFFFFFF, buffer, 8); // Max capabilities
        SMBUtil.writeInt4(0xFFFFFFFF, buffer, 12); // Max access

        // When
        int bytesRead = response.readBytesWireFormat(buffer, 0);

        // Then
        assertEquals(16, bytesRead);
        assertEquals((byte) 0xFF, response.getShareType());
        assertEquals(0xFFFFFFFF, response.getShareFlags());
        assertEquals(0xFFFFFFFF, response.getCapabilities());
        assertEquals(0xFFFFFFFF, response.getMaximalAccess());
    }

    @Test
    @DisplayName("Should handle buffer too small for reading")
    void testBufferTooSmall() {
        // Given
        byte[] buffer = new byte[15]; // Too small for 16-byte structure
        SMBUtil.writeInt2(16, buffer, 0);

        // When & Then
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            response.readBytesWireFormat(buffer, 0);
        });
    }

    @Test
    @DisplayName("Should handle offset exceeding buffer")
    void testOffsetExceedsBuffer() {
        // Given
        byte[] buffer = new byte[20];
        int offset = 10; // Only 10 bytes remaining, need 16
        SMBUtil.writeInt2(16, buffer, offset); // Write valid structure size

        // When & Then - Will throw SMBProtocolDecodingException when trying to read beyond buffer
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            response.readBytesWireFormat(buffer, offset);
        });
    }

    @DisplayName("Should read at different offsets correctly")
    @ParameterizedTest
    @ValueSource(ints = {0, 10, 50, 100, 200})
    void testReadAtDifferentOffsets(int offset) throws SMBProtocolDecodingException {
        // Given
        byte[] buffer = new byte[offset + 20];
        SMBUtil.writeInt2(16, buffer, offset);
        buffer[offset + 2] = 0x02; // PIPE
        buffer[offset + 3] = 0;
        SMBUtil.writeInt4(0x1234, buffer, offset + 4);
        SMBUtil.writeInt4(0x5678, buffer, offset + 8);
        SMBUtil.writeInt4(0x9ABC, buffer, offset + 12);

        // When
        int bytesRead = response.readBytesWireFormat(buffer, offset);

        // Then
        assertEquals(16, bytesRead);
        assertEquals((byte) 0x02, response.getShareType());
        assertEquals(0x1234, response.getShareFlags());
        assertEquals(0x5678, response.getCapabilities());
        assertEquals(0x9ABC, response.getMaximalAccess());
    }

    @Test
    @DisplayName("Should verify complete protocol compliance")
    void testProtocolCompliance() throws SMBProtocolDecodingException {
        // Given - exact SMB2 TREE_CONNECT response structure
        byte[] wireData = new byte[] {
            0x10, 0x00,  // StructureSize (must be 16)
            0x01,        // ShareType (DISK)
            0x00,        // Reserved
            0x01, 0x00, 0x00, 0x00,  // ShareFlags
            0x08, 0x00, 0x00, 0x00,  // Capabilities  
            (byte)0xFF, 0x01, 0x1F, 0x00   // MaximalAccess
        };
        
        // When
        int bytesRead = response.readBytesWireFormat(wireData, 0);

        // Then
        assertEquals(16, bytesRead);
        assertEquals(wireData.length, bytesRead);
        assertEquals((byte) 0x01, response.getShareType());
        assertEquals(0x00000001, response.getShareFlags());
        assertEquals(0x00000008, response.getCapabilities());
        assertEquals(0x001F01FF, response.getMaximalAccess());
    }

    @Test
    @DisplayName("Should not modify buffer during write operation")
    void testWriteDoesNotModifyBuffer() {
        // Given
        byte[] buffer = new byte[256];
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = (byte) (i & 0xFF);
        }
        byte[] originalBuffer = buffer.clone();

        // When
        int bytesWritten = response.writeBytesWireFormat(buffer, 10);

        // Then
        assertEquals(0, bytesWritten);
        assertArrayEquals(originalBuffer, buffer);
    }

    @Test
    @DisplayName("Should handle null configuration")
    void testNullConfiguration() {
        // When
        Smb2TreeConnectResponse responseWithNull = new Smb2TreeConnectResponse(null);
        
        // Then
        assertNotNull(responseWithNull);
    }

    @Test
    @DisplayName("Should test encryption flag detection")
    void testEncryptionFlagDetection() throws SMBProtocolDecodingException {
        // Given - response with encryption flag set
        byte[] buffer = createValidResponseBuffer(0, 0x8000, 0, 0);
        
        // When
        response.readBytesWireFormat(buffer, 0);
        
        // Then
        assertEquals(0x8000, response.getShareFlags() & 0x8000);
        assertTrue((response.getShareFlags() & Smb2TreeConnectResponse.SMB2_SHAREFLAG_ENCRYPT_DATA) != 0);
    }

    @Test
    @DisplayName("Should handle all capability flags")
    void testAllCapabilityFlags() throws SMBProtocolDecodingException {
        // Test each capability flag individually
        int[] capabilityFlags = {
            Smb2TreeConnectResponse.SMB2_SHARE_CAP_DFS,
            Smb2TreeConnectResponse.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY,
            Smb2TreeConnectResponse.SMB2_SHARE_CAP_SCALEOUT,
            Smb2TreeConnectResponse.SMB2_SHARE_CAP_CLUSTER,
            Smb2TreeConnectResponse.SMB2_SHARE_CAP_ASYMMETRIC
        };
        
        for (int flag : capabilityFlags) {
            response = new Smb2TreeConnectResponse(mockConfig);
            byte[] buffer = createValidResponseBuffer(0, 0, flag, 0);
            response.readBytesWireFormat(buffer, 0);
            assertEquals(flag, response.getCapabilities());
        }
    }

    @Test
    @DisplayName("Should handle combined capability flags")
    void testCombinedCapabilityFlags() throws SMBProtocolDecodingException {
        // Given - all capabilities combined
        int allCapabilities = Smb2TreeConnectResponse.SMB2_SHARE_CAP_DFS |
                            Smb2TreeConnectResponse.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY |
                            Smb2TreeConnectResponse.SMB2_SHARE_CAP_SCALEOUT |
                            Smb2TreeConnectResponse.SMB2_SHARE_CAP_CLUSTER |
                            Smb2TreeConnectResponse.SMB2_SHARE_CAP_ASYMMETRIC;
        
        byte[] buffer = createValidResponseBuffer(0, 0, allCapabilities, 0);
        
        // When
        response.readBytesWireFormat(buffer, 0);
        
        // Then
        assertEquals(allCapabilities, response.getCapabilities());
    }

    @Test
    @DisplayName("Should verify TreeConnectResponse interface implementation")
    void testTreeConnectResponseInterface() {
        // Then
        assertTrue(response instanceof TreeConnectResponse);
        
        // Test all interface methods
        assertNull(response.getService()); // getService returns null in SMB2
        assertEquals(response.getTreeId(), response.getTid());
    }

    /**
     * Helper method to create a valid response buffer
     */
    private byte[] createValidResponseBuffer(int shareType, int shareFlags, int capabilities, int maxAccess) {
        byte[] buffer = new byte[256];
        SMBUtil.writeInt2(16, buffer, 0);
        buffer[2] = (byte) shareType;
        buffer[3] = 0;
        SMBUtil.writeInt4(shareFlags, buffer, 4);
        SMBUtil.writeInt4(capabilities, buffer, 8);
        SMBUtil.writeInt4(maxAccess, buffer, 12);
        return buffer;
    }
}