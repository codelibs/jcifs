package org.codelibs.jcifs.smb.internal;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComTreeConnectAndXResponse;
import org.codelibs.jcifs.smb.internal.smb2.tree.Smb2TreeConnectResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Test class for TreeConnectResponse interface and its implementations.
 * Tests both SMB1 and SMB2 protocol implementations.
 */
@DisplayName("TreeConnectResponse Tests")
class TreeConnectResponseTest {

    @Mock
    private Configuration mockConfig;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    /**
     * Helper method to set private field value using reflection
     */
    private void setPrivateField(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    /**
     * Helper method to get private field value using reflection
     */
    private Object getPrivateField(Object obj, String fieldName) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }

    /**
     * Helper method to invoke protected/private method using reflection
     */
    private Object invokeMethod(Object obj, String methodName, Class<?>[] paramTypes, Object... args) throws Exception {
        Method method = obj.getClass().getDeclaredMethod(methodName, paramTypes);
        method.setAccessible(true);
        return method.invoke(obj, args);
    }

    /**
     * Tests for the TreeConnectResponse interface using a mock implementation
     */
    @Nested
    @DisplayName("Interface Contract Tests")
    class InterfaceTests {

        private TreeConnectResponse mockResponse;

        @BeforeEach
        void setUp() {
            mockResponse = mock(TreeConnectResponse.class);
        }

        @Test
        @DisplayName("Should return tree ID")
        void testGetTid() {
            // Given
            when(mockResponse.getTid()).thenReturn(12345);

            // When
            int tid = mockResponse.getTid();

            // Then
            assertEquals(12345, tid, "Should return the configured tree ID");
            verify(mockResponse).getTid();
        }

        @Test
        @DisplayName("Should return service type")
        void testGetService() {
            // Given
            when(mockResponse.getService()).thenReturn("A:");

            // When
            String service = mockResponse.getService();

            // Then
            assertEquals("A:", service, "Should return the service type");
            verify(mockResponse).getService();
        }

        @Test
        @DisplayName("Should indicate if share is in DFS")
        void testIsShareDfs() {
            // Given
            when(mockResponse.isShareDfs()).thenReturn(true);

            // When
            boolean isDfs = mockResponse.isShareDfs();

            // Then
            assertTrue(isDfs, "Should indicate DFS status");
            verify(mockResponse).isShareDfs();
        }

        @Test
        @DisplayName("Should validate tree ID")
        void testIsValidTid() {
            // Given
            when(mockResponse.isValidTid()).thenReturn(true);

            // When
            boolean isValid = mockResponse.isValidTid();

            // Then
            assertTrue(isValid, "Should indicate valid TID");
            verify(mockResponse).isValidTid();
        }
    }

    /**
     * Tests for SMB2 implementation of TreeConnectResponse
     */
    @Nested
    @DisplayName("SMB2 Implementation Tests")
    class Smb2TreeConnectResponseTests {

        private Smb2TreeConnectResponse response;

        @BeforeEach
        void setUp() {
            response = new Smb2TreeConnectResponse(mockConfig);
        }

        @Test
        @DisplayName("Should return tree ID from getTreeId")
        void testGetTid() {
            // Given
            response.setTreeId(54321);

            // When
            int tid = response.getTid();

            // Then
            assertEquals(54321, tid, "getTid should return tree ID");
        }

        @Test
        @DisplayName("Should validate tree ID correctly")
        void testIsValidTid() {
            // Test valid TID
            response.setTreeId(100);
            assertTrue(response.isValidTid(), "Positive tree ID should be valid");

            // Test invalid TID
            response.setTreeId(-1);
            assertFalse(response.isValidTid(), "Tree ID -1 should be invalid");
        }

        @Test
        @DisplayName("Should return null service for SMB2")
        void testGetService() {
            // When
            String service = response.getService();

            // Then
            assertNull(service, "SMB2 should return null service");
        }

        @Test
        @DisplayName("Should detect DFS from share flags")
        void testIsShareDfsWithShareFlags() throws Exception {
            // Test with DFS flag
            setPrivateField(response, "shareFlags", Smb2TreeConnectResponse.SMB2_SHAREFLAG_DFS);
            assertTrue(response.isShareDfs(), "Should detect DFS from DFS flag");

            // Test with DFS_ROOT flag
            setPrivateField(response, "shareFlags", Smb2TreeConnectResponse.SMB2_SHAREFLAG_DFS_ROOT);
            assertTrue(response.isShareDfs(), "Should detect DFS from DFS_ROOT flag");

            // Test with both flags
            setPrivateField(response, "shareFlags",
                    Smb2TreeConnectResponse.SMB2_SHAREFLAG_DFS | Smb2TreeConnectResponse.SMB2_SHAREFLAG_DFS_ROOT);
            assertTrue(response.isShareDfs(), "Should detect DFS from combined flags");

            // Test without DFS flags
            setPrivateField(response, "shareFlags", 0);
            setPrivateField(response, "capabilities", 0);
            assertFalse(response.isShareDfs(), "Should not detect DFS without flags");
        }

        @Test
        @DisplayName("Should detect DFS from capabilities")
        void testIsShareDfsWithCapabilities() throws Exception {
            // Given
            setPrivateField(response, "shareFlags", 0);
            setPrivateField(response, "capabilities", Smb2TreeConnectResponse.SMB2_SHARE_CAP_DFS);

            // When
            boolean isDfs = response.isShareDfs();

            // Then
            assertTrue(isDfs, "Should detect DFS from capabilities");
        }

        @Test
        @DisplayName("Should handle share type")
        void testShareType() throws Exception {
            // Test DISK share type
            setPrivateField(response, "shareType", Smb2TreeConnectResponse.SMB2_SHARE_TYPE_DISK);
            assertEquals(Smb2TreeConnectResponse.SMB2_SHARE_TYPE_DISK, response.getShareType(), "Should handle DISK share type");

            // Test PIPE share type
            setPrivateField(response, "shareType", Smb2TreeConnectResponse.SMB2_SHARE_TYPE_PIPE);
            assertEquals(Smb2TreeConnectResponse.SMB2_SHARE_TYPE_PIPE, response.getShareType(), "Should handle PIPE share type");

            // Test PRINT share type
            setPrivateField(response, "shareType", Smb2TreeConnectResponse.SMB2_SHARE_TYPE_PRINT);
            assertEquals(Smb2TreeConnectResponse.SMB2_SHARE_TYPE_PRINT, response.getShareType(), "Should handle PRINT share type");
        }

        @Test
        @DisplayName("Should handle share flags")
        void testShareFlags() throws Exception {
            // Test encryption flag
            setPrivateField(response, "shareFlags", Smb2TreeConnectResponse.SMB2_SHAREFLAG_ENCRYPT_DATA);
            assertEquals(Smb2TreeConnectResponse.SMB2_SHAREFLAG_ENCRYPT_DATA, response.getShareFlags(), "Should handle encryption flag");

            // Test multiple flags
            int combinedFlags = Smb2TreeConnectResponse.SMB2_SHAREFLAG_DFS | Smb2TreeConnectResponse.SMB2_SHAREFLAG_ENCRYPT_DATA;
            setPrivateField(response, "shareFlags", combinedFlags);
            assertEquals(combinedFlags, response.getShareFlags(), "Should handle multiple flags");
        }

        @Test
        @DisplayName("Should handle capabilities")
        void testCapabilities() throws Exception {
            // Test single capability
            setPrivateField(response, "capabilities", Smb2TreeConnectResponse.SMB2_SHARE_CAP_DFS);
            assertEquals(Smb2TreeConnectResponse.SMB2_SHARE_CAP_DFS, response.getCapabilities(), "Should handle DFS capability");

            // Test multiple capabilities
            int combinedCaps = Smb2TreeConnectResponse.SMB2_SHARE_CAP_DFS | Smb2TreeConnectResponse.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY;
            setPrivateField(response, "capabilities", combinedCaps);
            assertEquals(combinedCaps, response.getCapabilities(), "Should handle multiple capabilities");
        }

        @Test
        @DisplayName("Should handle maximal access")
        void testMaximalAccess() throws Exception {
            // Given
            setPrivateField(response, "maximalAccess", 0x001F01FF);

            // When
            int access = response.getMaximalAccess();

            // Then
            assertEquals(0x001F01FF, access, "Should return maximal access value");
        }

        @Test
        @DisplayName("Should decode response from bytes correctly")
        void testReadBytesWireFormat() throws Exception {
            // Given - Prepare a valid SMB2 Tree Connect Response buffer
            byte[] buffer = new byte[16];
            // Structure size (16)
            buffer[0] = 0x10;
            buffer[1] = 0x00;
            // Share type (DISK)
            buffer[2] = Smb2TreeConnectResponse.SMB2_SHARE_TYPE_DISK;
            // Reserved
            buffer[3] = 0;
            // Share flags (DFS)
            buffer[4] = 0x01;
            buffer[5] = 0x00;
            buffer[6] = 0x00;
            buffer[7] = 0x00;
            // Capabilities (DFS)
            buffer[8] = 0x08;
            buffer[9] = 0x00;
            buffer[10] = 0x00;
            buffer[11] = 0x00;
            // Maximal access
            buffer[12] = (byte) 0xFF;
            buffer[13] = 0x01;
            buffer[14] = 0x1F;
            buffer[15] = 0x00;

            // When
            int bytesRead = (int) invokeMethod(response, "readBytesWireFormat", new Class[] { byte[].class, int.class }, buffer, 0);

            // Then
            assertEquals(16, bytesRead, "Should read 16 bytes");
            assertEquals(Smb2TreeConnectResponse.SMB2_SHARE_TYPE_DISK, response.getShareType(), "Should decode share type");
            assertEquals(0x01, response.getShareFlags(), "Should decode share flags");
            assertEquals(0x08, response.getCapabilities(), "Should decode capabilities");
            assertEquals(0x001F01FF, response.getMaximalAccess(), "Should decode maximal access");
            assertTrue(response.isShareDfs(), "Should detect DFS from decoded data");
        }

        @Test
        @DisplayName("Should throw exception for invalid structure size")
        void testReadBytesWireFormatInvalidSize() throws Exception {
            // Given - Invalid structure size
            byte[] buffer = new byte[16];
            buffer[0] = 0x0F; // Invalid size (15 instead of 16)
            buffer[1] = 0x00;

            // When & Then - InvocationTargetException wraps the actual exception when using reflection
            Exception exception = assertThrows(Exception.class,
                    () -> invokeMethod(response, "readBytesWireFormat", new Class[] { byte[].class, int.class }, buffer, 0),
                    "Should throw exception for invalid structure size");

            // Verify the actual cause is SMBProtocolDecodingException
            assertTrue(exception instanceof java.lang.reflect.InvocationTargetException, "Should be wrapped in InvocationTargetException");
            Throwable cause = exception.getCause();
            assertTrue(cause instanceof SMBProtocolDecodingException, "Actual cause should be SMBProtocolDecodingException");
            assertEquals("Structure size is not 16", cause.getMessage(), "Should have correct error message");
        }

        @Test
        @DisplayName("Should write empty bytes for wire format")
        void testWriteBytesWireFormat() throws Exception {
            // Given
            byte[] buffer = new byte[100];

            // When
            int bytesWritten = (int) invokeMethod(response, "writeBytesWireFormat", new Class[] { byte[].class, int.class }, buffer, 0);

            // Then
            assertEquals(0, bytesWritten, "Should write 0 bytes for response");
        }
    }

    /**
     * Tests for SMB1 implementation of TreeConnectResponse
     */
    @Nested
    @DisplayName("SMB1 Implementation Tests")
    class SmbComTreeConnectAndXResponseTests {

        private SmbComTreeConnectAndXResponse response;
        private ServerMessageBlock mockAndx;

        @BeforeEach
        void setUp() {
            mockAndx = mock(ServerMessageBlock.class);
            response = new SmbComTreeConnectAndXResponse(mockConfig, mockAndx);
        }

        @Test
        @DisplayName("Should return service type")
        void testGetService() throws Exception {
            // Given
            setPrivateField(response, "service", "IPC");

            // When
            String service = response.getService();

            // Then
            assertEquals("IPC", service, "Should return the service type");
        }

        @Test
        @DisplayName("Should return native file system")
        void testGetNativeFileSystem() throws Exception {
            // Given
            setPrivateField(response, "nativeFileSystem", "NTFS");

            // When
            String fs = response.getNativeFileSystem();

            // Then
            assertEquals("NTFS", fs, "Should return the native file system");
        }

        @Test
        @DisplayName("Should indicate DFS support")
        void testIsShareDfs() throws Exception {
            // Test with DFS flag set
            setPrivateField(response, "shareIsInDfs", true);
            assertTrue(response.isShareDfs(), "Should indicate share is in DFS");

            // Test with DFS flag not set
            setPrivateField(response, "shareIsInDfs", false);
            assertFalse(response.isShareDfs(), "Should indicate share is not in DFS");
        }

        @Test
        @DisplayName("Should indicate search bits support")
        void testIsSupportSearchBits() throws Exception {
            // Test with search bits supported
            setPrivateField(response, "supportSearchBits", true);
            assertTrue(response.isSupportSearchBits(), "Should indicate search bits support");

            // Test without search bits support
            setPrivateField(response, "supportSearchBits", false);
            assertFalse(response.isSupportSearchBits(), "Should indicate no search bits support");
        }

        @Test
        @DisplayName("Should validate tree ID correctly")
        void testIsValidTid() {
            // Test valid TID
            response.setTid(100);
            assertTrue(response.isValidTid(), "TID 100 should be valid");

            // Test invalid TID (0xFFFF)
            response.setTid(0xFFFF);
            assertFalse(response.isValidTid(), "TID 0xFFFF should be invalid");
        }

        @Test
        @DisplayName("Should decode parameter words correctly")
        void testReadParameterWordsWireFormat() throws Exception {
            // Given - Buffer with flags
            byte[] buffer = new byte[2];
            buffer[0] = 0x03; // Both SMB_SUPPORT_SEARCH_BITS and SMB_SHARE_IS_IN_DFS

            // When
            int bytesRead =
                    (int) invokeMethod(response, "readParameterWordsWireFormat", new Class[] { byte[].class, int.class }, buffer, 0);

            // Then
            assertEquals(2, bytesRead, "Should read 2 bytes");
            assertTrue(response.isSupportSearchBits(), "Should decode search bits flag");
            assertTrue(response.isShareDfs(), "Should decode DFS flag");
        }

        @Test
        @DisplayName("Should decode bytes correctly")
        void testReadBytesWireFormat() throws Exception {
            // Given - Service string in ASCII
            String testService = "A:";
            byte[] serviceBytes = testService.getBytes("ASCII");
            byte[] buffer = new byte[serviceBytes.length + 1];
            System.arraycopy(serviceBytes, 0, buffer, 0, serviceBytes.length);
            buffer[serviceBytes.length] = 0; // Null terminator

            // When
            int bytesRead = (int) invokeMethod(response, "readBytesWireFormat", new Class[] { byte[].class, int.class }, buffer, 0);

            // Then
            assertEquals(serviceBytes.length + 1, bytesRead, "Should read service string plus terminator");
            assertEquals(testService, response.getService(), "Should decode service string");
        }

        @Test
        @DisplayName("Should write empty parameter words")
        void testWriteParameterWordsWireFormat() throws Exception {
            // Given
            byte[] buffer = new byte[100];

            // When
            int bytesWritten =
                    (int) invokeMethod(response, "writeParameterWordsWireFormat", new Class[] { byte[].class, int.class }, buffer, 0);

            // Then
            assertEquals(0, bytesWritten, "Should write 0 bytes for response");
        }

        @Test
        @DisplayName("Should write empty bytes")
        void testWriteBytesWireFormat() throws Exception {
            // Given
            byte[] buffer = new byte[100];

            // When
            int bytesWritten = (int) invokeMethod(response, "writeBytesWireFormat", new Class[] { byte[].class, int.class }, buffer, 0);

            // Then
            assertEquals(0, bytesWritten, "Should write 0 bytes for response");
        }

        @Test
        @DisplayName("Should generate correct toString representation")
        void testToString() throws Exception {
            // Given
            setPrivateField(response, "supportSearchBits", true);
            setPrivateField(response, "shareIsInDfs", true);
            setPrivateField(response, "service", "IPC");
            setPrivateField(response, "nativeFileSystem", "NTFS");

            // When
            String str = response.toString();

            // Then
            assertNotNull(str, "toString should not return null");
            assertTrue(str.contains("SmbComTreeConnectAndXResponse"), "Should contain class name");
            assertTrue(str.contains("supportSearchBits=true"), "Should contain search bits flag");
            assertTrue(str.contains("shareIsInDfs=true"), "Should contain DFS flag");
            assertTrue(str.contains("service=IPC"), "Should contain service");
            assertTrue(str.contains("nativeFileSystem=NTFS"), "Should contain file system");
        }
    }

    /**
     * Tests for edge cases and error conditions
     */
    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle null configuration gracefully")
        void testNullConfiguration() {
            // When & Then - Should not throw exception
            assertDoesNotThrow(() -> {
                new Smb2TreeConnectResponse(null);
            }, "Should handle null configuration");
        }

        @Test
        @DisplayName("Should handle boundary values for tree ID")
        void testBoundaryTreeIds() {
            Smb2TreeConnectResponse smb2Response = new Smb2TreeConnectResponse(mockConfig);

            // Test minimum valid TID
            smb2Response.setTreeId(0);
            assertTrue(smb2Response.isValidTid(), "TID 0 should be valid");

            // Test maximum valid TID
            smb2Response.setTreeId(Integer.MAX_VALUE);
            assertTrue(smb2Response.isValidTid(), "Maximum TID should be valid");

            // Test invalid TID
            smb2Response.setTreeId(-1);
            assertFalse(smb2Response.isValidTid(), "Negative TID should be invalid");
        }

        @Test
        @DisplayName("Should handle all share types correctly")
        void testAllShareTypes() throws Exception {
            Smb2TreeConnectResponse response = new Smb2TreeConnectResponse(mockConfig);

            // Test all defined share types
            byte[] shareTypes = { Smb2TreeConnectResponse.SMB2_SHARE_TYPE_DISK, Smb2TreeConnectResponse.SMB2_SHARE_TYPE_PIPE,
                    Smb2TreeConnectResponse.SMB2_SHARE_TYPE_PRINT };

            for (byte shareType : shareTypes) {
                setPrivateField(response, "shareType", shareType);
                assertEquals(shareType, response.getShareType(), "Should handle share type: " + shareType);
            }
        }

        @Test
        @DisplayName("Should handle combined flags correctly")
        void testCombinedFlags() throws Exception {
            Smb2TreeConnectResponse response = new Smb2TreeConnectResponse(mockConfig);

            // Test multiple share flags combined
            int combinedFlags = Smb2TreeConnectResponse.SMB2_SHAREFLAG_DFS | Smb2TreeConnectResponse.SMB2_SHAREFLAG_ENCRYPT_DATA
                    | Smb2TreeConnectResponse.SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM;

            setPrivateField(response, "shareFlags", combinedFlags);
            assertEquals(combinedFlags, response.getShareFlags(), "Should handle combined flags");
            assertTrue(response.isShareDfs(), "Should detect DFS in combined flags");

            // Test multiple capabilities combined
            int combinedCaps = Smb2TreeConnectResponse.SMB2_SHARE_CAP_DFS | Smb2TreeConnectResponse.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY
                    | Smb2TreeConnectResponse.SMB2_SHARE_CAP_SCALEOUT;

            setPrivateField(response, "capabilities", combinedCaps);
            assertEquals(combinedCaps, response.getCapabilities(), "Should handle combined capabilities");
        }

        @Test
        @DisplayName("Should handle empty service string")
        void testEmptyService() throws Exception {
            SmbComTreeConnectAndXResponse response = new SmbComTreeConnectAndXResponse(mockConfig, null);

            // Test empty service
            setPrivateField(response, "service", "");
            assertEquals("", response.getService(), "Should handle empty service string");

            // Test null service (default)
            setPrivateField(response, "service", null);
            assertNull(response.getService(), "Should handle null service");
        }

        @Test
        @DisplayName("Should handle various caching flags")
        void testCachingFlags() throws Exception {
            Smb2TreeConnectResponse response = new Smb2TreeConnectResponse(mockConfig);

            // Test manual caching
            setPrivateField(response, "shareFlags", Smb2TreeConnectResponse.SMB2_SHAREFLAG_MANUAL_CACHING);
            assertEquals(Smb2TreeConnectResponse.SMB2_SHAREFLAG_MANUAL_CACHING, response.getShareFlags(),
                    "Should handle manual caching flag");

            // Test auto caching
            setPrivateField(response, "shareFlags", Smb2TreeConnectResponse.SMB2_SHAREFLAG_AUTO_CACHING);
            assertEquals(Smb2TreeConnectResponse.SMB2_SHAREFLAG_AUTO_CACHING, response.getShareFlags(), "Should handle auto caching flag");

            // Test VDO caching
            setPrivateField(response, "shareFlags", Smb2TreeConnectResponse.SMB2_SHAREFLAG_VDO_CACHING);
            assertEquals(Smb2TreeConnectResponse.SMB2_SHAREFLAG_VDO_CACHING, response.getShareFlags(), "Should handle VDO caching flag");
        }

        @Test
        @DisplayName("Should handle cluster capabilities")
        void testClusterCapabilities() throws Exception {
            Smb2TreeConnectResponse response = new Smb2TreeConnectResponse(mockConfig);

            // Test cluster capability
            setPrivateField(response, "capabilities", Smb2TreeConnectResponse.SMB2_SHARE_CAP_CLUSTER);
            assertEquals(Smb2TreeConnectResponse.SMB2_SHARE_CAP_CLUSTER, response.getCapabilities(), "Should handle cluster capability");

            // Test asymmetric capability
            setPrivateField(response, "capabilities", Smb2TreeConnectResponse.SMB2_SHARE_CAP_ASYMMETRIC);
            assertEquals(Smb2TreeConnectResponse.SMB2_SHARE_CAP_ASYMMETRIC, response.getCapabilities(),
                    "Should handle asymmetric capability");
        }
    }
}