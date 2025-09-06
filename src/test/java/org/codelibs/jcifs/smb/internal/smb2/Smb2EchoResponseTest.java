package org.codelibs.jcifs.smb.internal.smb2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.NtStatus;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class Smb2EchoResponseTest {

    @Mock
    private Configuration mockConfig;

    @Mock
    private Smb2SigningDigest mockDigest;

    private Smb2EchoResponse echoResponse;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        echoResponse = new Smb2EchoResponse(mockConfig);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create response with configuration")
        void testConstructor() {
            Smb2EchoResponse response = new Smb2EchoResponse(mockConfig);
            assertNotNull(response);
            assertEquals(mockConfig, response.getConfig());
        }

        @Test
        @DisplayName("Should extend ServerMessageBlock2Response")
        void testInheritance() {
            assertTrue(echoResponse instanceof ServerMessageBlock2Response);
        }
    }

    @Nested
    @DisplayName("Write Bytes Wire Format Tests")
    class WriteBytesWireFormatTests {

        @Test
        @DisplayName("Should return 0 for writeBytesWireFormat")
        void testWriteBytesWireFormat() {
            byte[] buffer = new byte[1024];
            int result = echoResponse.writeBytesWireFormat(buffer, 0);
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should handle different buffer positions")
        void testWriteBytesWireFormatDifferentPositions() {
            byte[] buffer = new byte[1024];

            assertEquals(0, echoResponse.writeBytesWireFormat(buffer, 0));
            assertEquals(0, echoResponse.writeBytesWireFormat(buffer, 100));
            assertEquals(0, echoResponse.writeBytesWireFormat(buffer, 500));
        }

        @Test
        @DisplayName("Should not modify buffer")
        void testWriteBytesWireFormatNoModification() {
            byte[] buffer = new byte[1024];
            byte[] originalBuffer = buffer.clone();

            echoResponse.writeBytesWireFormat(buffer, 0);

            assertArrayEquals(originalBuffer, buffer);
        }
    }

    @Nested
    @DisplayName("Read Bytes Wire Format Tests")
    class ReadBytesWireFormatTests {

        @Test
        @DisplayName("Should read valid structure size of 4")
        void testReadBytesWireFormatValid() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[1024];
            int bufferIndex = 100;

            // Write structure size = 4
            SMBUtil.writeInt2(4, buffer, bufferIndex);

            int result = echoResponse.readBytesWireFormat(buffer, bufferIndex);

            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should throw exception for invalid structure size")
        void testReadBytesWireFormatInvalidSize() {
            byte[] buffer = new byte[1024];
            int bufferIndex = 100;

            // Write invalid structure size = 8
            SMBUtil.writeInt2(8, buffer, bufferIndex);

            SMBProtocolDecodingException exception =
                    assertThrows(SMBProtocolDecodingException.class, () -> echoResponse.readBytesWireFormat(buffer, bufferIndex));

            assertEquals("Expected structureSize = 4", exception.getMessage());
        }

        @ParameterizedTest
        @ValueSource(ints = { 0, 1, 2, 3, 5, 6, 100, 65535 })
        @DisplayName("Should throw exception for various invalid structure sizes")
        void testReadBytesWireFormatVariousInvalidSizes(int structureSize) {
            byte[] buffer = new byte[1024];
            int bufferIndex = 50;

            SMBUtil.writeInt2(structureSize, buffer, bufferIndex);

            SMBProtocolDecodingException exception =
                    assertThrows(SMBProtocolDecodingException.class, () -> echoResponse.readBytesWireFormat(buffer, bufferIndex));

            assertEquals("Expected structureSize = 4", exception.getMessage());
        }

        @Test
        @DisplayName("Should handle different buffer positions correctly")
        void testReadBytesWireFormatDifferentPositions() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[1024];

            // Test at different positions
            int[] positions = { 0, 50, 100, 500, 800 };

            for (int position : positions) {
                SMBUtil.writeInt2(4, buffer, position);

                int result = echoResponse.readBytesWireFormat(buffer, position);
                assertEquals(0, result, "Failed at position " + position);
            }
        }

        @Test
        @DisplayName("Should not read beyond structure size field")
        void testReadBytesWireFormatBoundary() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[10];
            int bufferIndex = 0;

            // Write structure size = 4
            SMBUtil.writeInt2(4, buffer, bufferIndex);

            // Fill rest of buffer with garbage
            for (int i = 2; i < buffer.length; i++) {
                buffer[i] = (byte) 0xFF;
            }

            // Should only read the structure size (2 bytes) and not go beyond
            int result = echoResponse.readBytesWireFormat(buffer, bufferIndex);
            assertEquals(0, result);
        }
    }

    @Nested
    @DisplayName("Response State Tests")
    class ResponseStateTests {

        @Test
        @DisplayName("Should track received state")
        void testReceivedState() {
            assertFalse(echoResponse.isReceived());

            echoResponse.received();

            assertTrue(echoResponse.isReceived());
        }

        @Test
        @DisplayName("Should track error state")
        void testErrorState() {
            assertFalse(echoResponse.isError());

            echoResponse.error();

            assertTrue(echoResponse.isError());
        }

        @Test
        @DisplayName("Should handle exception")
        void testException() {
            Exception testException = new Exception("Test exception");

            assertFalse(echoResponse.isError());
            assertFalse(echoResponse.isReceived());
            assertNull(echoResponse.getException());

            echoResponse.exception(testException);

            assertTrue(echoResponse.isError());
            assertTrue(echoResponse.isReceived());
            assertEquals(testException, echoResponse.getException());
        }

        @Test
        @DisplayName("Should clear received state")
        void testClearReceived() {
            echoResponse.received();
            assertTrue(echoResponse.isReceived());

            echoResponse.clearReceived();

            assertFalse(echoResponse.isReceived());
        }

        @Test
        @DisplayName("Should handle async operations")
        void testAsyncOperations() {
            assertFalse(echoResponse.isAsyncHandled());

            echoResponse.setAsyncHandled(true);

            assertTrue(echoResponse.isAsyncHandled());

            echoResponse.setAsyncHandled(false);

            assertFalse(echoResponse.isAsyncHandled());
        }
    }

    @Nested
    @DisplayName("Expiration Tests")
    class ExpirationTests {

        @Test
        @DisplayName("Should manage expiration time")
        void testExpiration() {
            assertNull(echoResponse.getExpiration());

            Long expiration = System.currentTimeMillis() + 10000L;
            echoResponse.setExpiration(expiration);

            assertEquals(expiration, echoResponse.getExpiration());
        }

        @Test
        @DisplayName("Should handle null expiration")
        void testNullExpiration() {
            Long expiration = 1000L;
            echoResponse.setExpiration(expiration);
            assertEquals(expiration, echoResponse.getExpiration());

            echoResponse.setExpiration(null);

            assertNull(echoResponse.getExpiration());
        }
    }

    @Nested
    @DisplayName("Signature Verification Tests")
    class SignatureVerificationTests {

        @Test
        @DisplayName("Should verify signature when digest is present and successful")
        void testVerifySignatureSuccess() throws Exception {
            byte[] buffer = new byte[1024];
            echoResponse.setDigest(mockDigest);
            setStatus(echoResponse, NtStatus.NT_STATUS_SUCCESS);

            when(mockConfig.isRequireSecureNegotiate()).thenReturn(true);
            when(mockDigest.verify(buffer, 0, 100, 0, echoResponse)).thenReturn(true);

            boolean result = echoResponse.verifySignature(buffer, 0, 100);

            assertTrue(result);
            assertFalse(echoResponse.isVerifyFailed());
            verify(mockDigest).verify(buffer, 0, 100, 0, echoResponse);
        }

        @Test
        @DisplayName("Should fail signature verification when digest verification fails")
        void testVerifySignatureFailed() throws Exception {
            byte[] buffer = new byte[1024];
            echoResponse.setDigest(mockDigest);
            setStatus(echoResponse, NtStatus.NT_STATUS_SUCCESS);

            when(mockConfig.isRequireSecureNegotiate()).thenReturn(true);
            when(mockDigest.verify(buffer, 0, 100, 0, echoResponse)).thenReturn(false);

            boolean result = echoResponse.verifySignature(buffer, 0, 100);

            assertFalse(result);
            assertTrue(echoResponse.isVerifyFailed());
        }

        @Test
        @DisplayName("Should skip verification when digest is null")
        void testVerifySignatureNoDigest() {
            byte[] buffer = new byte[1024];
            echoResponse.setDigest(null);

            boolean result = echoResponse.verifySignature(buffer, 0, 100);

            assertTrue(result);
            assertFalse(echoResponse.isVerifyFailed());
        }

        @Test
        @DisplayName("Should skip verification for async responses")
        void testVerifySignatureAsync() throws Exception {
            byte[] buffer = new byte[1024];
            echoResponse.setDigest(mockDigest);
            setAsync(echoResponse, true);

            boolean result = echoResponse.verifySignature(buffer, 0, 100);

            assertTrue(result);
            assertFalse(echoResponse.isVerifyFailed());
            verify(mockDigest, never()).verify(any(), anyInt(), anyInt(), anyInt(), any());
        }
    }

    @Nested
    @DisplayName("Credit Management Tests")
    class CreditManagementTests {

        @Test
        @DisplayName("Should get granted credits from credit field")
        void testGetGrantedCredits() {
            int credits = 15;
            echoResponse.setCredit(credits);

            assertEquals(credits, echoResponse.getGrantedCredits());
        }
    }

    @Nested
    @DisplayName("Error Code Tests")
    class ErrorCodeTests {

        @Test
        @DisplayName("Should get error code from status")
        void testGetErrorCode() throws Exception {
            int status = NtStatus.NT_STATUS_ACCESS_DENIED;
            setStatus(echoResponse, status);

            assertEquals(status, echoResponse.getErrorCode());
        }
    }

    @Nested
    @DisplayName("Signed Flag Tests")
    class SignedFlagTests {

        @Test
        @DisplayName("Should detect signed flag")
        void testIsSigned() {
            assertFalse(echoResponse.isSigned());

            echoResponse.addFlags(ServerMessageBlock2.SMB2_FLAGS_SIGNED);

            assertTrue(echoResponse.isSigned());
        }

        @Test
        @DisplayName("Should handle multiple flags correctly")
        void testIsSignedWithMultipleFlags() {
            echoResponse.addFlags(ServerMessageBlock2.SMB2_FLAGS_ASYNC_COMMAND);
            assertFalse(echoResponse.isSigned());

            echoResponse.addFlags(ServerMessageBlock2.SMB2_FLAGS_SIGNED);
            assertTrue(echoResponse.isSigned());
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should handle complete echo response workflow")
        void testCompleteEchoResponseWorkflow() throws Exception {
            // Setup
            byte[] buffer = new byte[1024];
            int bufferIndex = 64;
            SMBUtil.writeInt2(4, buffer, bufferIndex);

            // Configure response
            echoResponse.setDigest(mockDigest);
            setStatus(echoResponse, NtStatus.NT_STATUS_SUCCESS);
            when(mockConfig.isRequireSecureNegotiate()).thenReturn(false);

            // Read the response
            int bytesRead = echoResponse.readBytesWireFormat(buffer, bufferIndex);
            assertEquals(0, bytesRead);

            // Write response (echo responses don't write data)
            int bytesWritten = echoResponse.writeBytesWireFormat(buffer, 0);
            assertEquals(0, bytesWritten);

            // Mark as received
            echoResponse.received();
            assertTrue(echoResponse.isReceived());
            assertFalse(echoResponse.isError());
        }

        @Test
        @DisplayName("Should handle error scenario")
        void testErrorScenario() {
            byte[] buffer = new byte[1024];
            int bufferIndex = 64;

            // Write invalid structure size
            SMBUtil.writeInt2(10, buffer, bufferIndex);

            // Should throw exception
            assertThrows(SMBProtocolDecodingException.class, () -> echoResponse.readBytesWireFormat(buffer, bufferIndex));

            // Set error state
            Exception error = new SMBProtocolDecodingException("Test error");
            echoResponse.exception(error);

            assertTrue(echoResponse.isError());
            assertTrue(echoResponse.isReceived());
            assertEquals(error, echoResponse.getException());
        }
    }

    // Helper methods to set protected fields via reflection
    private void setStatus(ServerMessageBlock2 smb, int status) throws Exception {
        Field statusField = ServerMessageBlock2.class.getDeclaredField("status");
        statusField.setAccessible(true);
        statusField.setInt(smb, status);
    }

    private void setAsync(ServerMessageBlock2 smb, boolean async) throws Exception {
        Field asyncField = ServerMessageBlock2.class.getDeclaredField("async");
        asyncField.setAccessible(true);
        asyncField.setBoolean(smb, async);
    }
}
