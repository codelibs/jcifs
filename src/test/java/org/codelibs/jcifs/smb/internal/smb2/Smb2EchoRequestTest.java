package org.codelibs.jcifs.smb.internal.smb2;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class Smb2EchoRequestTest {

    @Mock
    private Configuration mockConfig;

    @Mock
    private CIFSContext mockContext;

    private Smb2EchoRequest echoRequest;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(mockContext.getConfig()).thenReturn(mockConfig);
        echoRequest = new Smb2EchoRequest(mockConfig);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create echo request with correct command")
        void testConstructor() throws Exception {
            Smb2EchoRequest request = new Smb2EchoRequest(mockConfig);
            assertNotNull(request);

            // Verify command is set to SMB2_ECHO (0x000D)
            assertEquals(0x000D, request.getCommand());

            // Verify configuration is set
            Field configField = ServerMessageBlock2.class.getDeclaredField("config");
            configField.setAccessible(true);
            assertEquals(mockConfig, configField.get(request));
        }

        @Test
        @DisplayName("Should handle null configuration")
        void testConstructorWithNullConfig() {
            assertDoesNotThrow(() -> {
                Smb2EchoRequest request = new Smb2EchoRequest(null);
                assertNotNull(request);
            });
        }
    }

    @Nested
    @DisplayName("CreateResponse Tests")
    class CreateResponseTests {

        @Test
        @DisplayName("Should create correct response type")
        void testCreateResponse() {
            Smb2EchoResponse response = echoRequest.createResponse(mockContext, echoRequest);

            assertNotNull(response);
            assertInstanceOf(Smb2EchoResponse.class, response);
        }

        @Test
        @DisplayName("Should create response with correct configuration")
        void testCreateResponseConfiguration() throws Exception {
            Smb2EchoResponse response = echoRequest.createResponse(mockContext, echoRequest);

            // Verify the response has the correct configuration
            Field configField = ServerMessageBlock2.class.getDeclaredField("config");
            configField.setAccessible(true);
            assertEquals(mockConfig, configField.get(response));
        }

        @Test
        @DisplayName("Should handle null context")
        void testCreateResponseWithNullContext() {
            CIFSContext nullContext = mock(CIFSContext.class);
            when(nullContext.getConfig()).thenReturn(null);

            assertDoesNotThrow(() -> {
                Smb2EchoResponse response = echoRequest.createResponse(nullContext, echoRequest);
                assertNotNull(response);
            });
        }
    }

    @Nested
    @DisplayName("Size Tests")
    class SizeTests {

        @Test
        @DisplayName("Should return correct size")
        void testSize() {
            int expectedSize = Smb2Constants.SMB2_HEADER_LENGTH + 4;
            // size8 rounds up to 8-byte boundary
            int expectedAlignedSize = (expectedSize + 7) & ~7;

            assertEquals(expectedAlignedSize, echoRequest.size());
        }

        @Test
        @DisplayName("Size should be consistent across multiple calls")
        void testSizeConsistency() {
            int size1 = echoRequest.size();
            int size2 = echoRequest.size();

            assertEquals(size1, size2);
        }

        @Test
        @DisplayName("Size should be 72 bytes (64 header + 4 body aligned to 8)")
        void testExactSize() {
            // SMB2_HEADER_LENGTH = 64, body = 4, total = 68
            // size8 aligns to 8-byte boundary: (68 + 7) & ~7 = 72
            assertEquals(72, echoRequest.size());
        }
    }

    @Nested
    @DisplayName("WriteBytesWireFormat Tests")
    class WriteBytesWireFormatTests {

        @Test
        @DisplayName("Should write correct structure size")
        void testWriteBytesWireFormat() {
            byte[] buffer = new byte[100];
            int startIndex = 10;

            int bytesWritten = echoRequest.writeBytesWireFormat(buffer, startIndex);

            // Should write 4 bytes
            assertEquals(4, bytesWritten);

            // Should write structure size of 4
            assertEquals(4, SMBUtil.readInt2(buffer, startIndex));
        }

        @Test
        @DisplayName("Should not modify bytes outside written range")
        void testWriteBytesDoesNotOverflow() {
            byte[] buffer = new byte[100];
            // Fill buffer with known values
            for (int i = 0; i < buffer.length; i++) {
                buffer[i] = (byte) 0xFF;
            }

            int startIndex = 50;
            echoRequest.writeBytesWireFormat(buffer, startIndex);

            // Check bytes before written area are unchanged
            for (int i = 0; i < startIndex; i++) {
                assertEquals((byte) 0xFF, buffer[i]);
            }

            // Check bytes after written area are unchanged
            for (int i = startIndex + 4; i < buffer.length; i++) {
                assertEquals((byte) 0xFF, buffer[i]);
            }
        }

        @Test
        @DisplayName("Should handle zero offset")
        void testWriteBytesAtZeroOffset() {
            byte[] buffer = new byte[10];

            int bytesWritten = echoRequest.writeBytesWireFormat(buffer, 0);

            assertEquals(4, bytesWritten);
            assertEquals(4, SMBUtil.readInt2(buffer, 0));
        }

        @Test
        @DisplayName("Should handle maximum offset")
        void testWriteBytesAtMaxOffset() {
            byte[] buffer = new byte[1000];
            int offset = buffer.length - 4;

            int bytesWritten = echoRequest.writeBytesWireFormat(buffer, offset);

            assertEquals(4, bytesWritten);
            assertEquals(4, SMBUtil.readInt2(buffer, offset));
        }
    }

    @Nested
    @DisplayName("ReadBytesWireFormat Tests")
    class ReadBytesWireFormatTests {

        @Test
        @DisplayName("Should always return 0")
        void testReadBytesWireFormat() {
            byte[] buffer = new byte[100];

            int bytesRead = echoRequest.readBytesWireFormat(buffer, 0);

            assertEquals(0, bytesRead);
        }

        @Test
        @DisplayName("Should return 0 regardless of buffer content")
        void testReadBytesWithVariousBufferContent() {
            byte[] emptyBuffer = new byte[100];
            byte[] fullBuffer = new byte[100];
            for (int i = 0; i < fullBuffer.length; i++) {
                fullBuffer[i] = (byte) i;
            }

            assertEquals(0, echoRequest.readBytesWireFormat(emptyBuffer, 0));
            assertEquals(0, echoRequest.readBytesWireFormat(fullBuffer, 50));
        }

        @Test
        @DisplayName("Should handle null buffer")
        void testReadBytesWithNullBuffer() {
            // This is expected behavior for echo request - no reading needed
            assertDoesNotThrow(() -> {
                int result = echoRequest.readBytesWireFormat(null, 0);
                assertEquals(0, result);
            });
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should work as complete request-response cycle")
        void testCompleteRequestResponseCycle() {
            // Create request
            Smb2EchoRequest request = new Smb2EchoRequest(mockConfig);

            // Verify request properties
            assertEquals(0x000D, request.getCommand());
            assertEquals(72, request.size());

            // Create response
            Smb2EchoResponse response = request.createResponse(mockContext, request);
            assertNotNull(response);

            // Write request to buffer
            byte[] buffer = new byte[100];
            int written = request.writeBytesWireFormat(buffer, 0);
            assertEquals(4, written);

            // Verify written data
            assertEquals(4, SMBUtil.readInt2(buffer, 0));
        }

        @Test
        @DisplayName("Should handle multiple requests")
        void testMultipleRequests() {
            Smb2EchoRequest request1 = new Smb2EchoRequest(mockConfig);
            Smb2EchoRequest request2 = new Smb2EchoRequest(mockConfig);

            // Both should have same properties
            assertEquals(request1.getCommand(), request2.getCommand());
            assertEquals(request1.size(), request2.size());

            // But be different objects
            assertNotSame(request1, request2);

            // Both should create valid responses
            Smb2EchoResponse response1 = request1.createResponse(mockContext, request1);
            Smb2EchoResponse response2 = request2.createResponse(mockContext, request2);

            assertNotNull(response1);
            assertNotNull(response2);
            assertNotSame(response1, response2);
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("Should handle buffer boundary conditions")
        void testBufferBoundaryConditions() {
            // Minimum size buffer
            byte[] minBuffer = new byte[4];
            int written = echoRequest.writeBytesWireFormat(minBuffer, 0);
            assertEquals(4, written);
            assertEquals(4, SMBUtil.readInt2(minBuffer, 0));

            // Large buffer
            byte[] largeBuffer = new byte[10000];
            written = echoRequest.writeBytesWireFormat(largeBuffer, 5000);
            assertEquals(4, written);
            assertEquals(4, SMBUtil.readInt2(largeBuffer, 5000));
        }

        @Test
        @DisplayName("Should maintain thread safety")
        void testThreadSafety() throws InterruptedException {
            int threadCount = 10;
            Thread[] threads = new Thread[threadCount];
            boolean[] success = new boolean[threadCount];

            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                threads[i] = new Thread(() -> {
                    try {
                        Smb2EchoRequest req = new Smb2EchoRequest(mockConfig);
                        byte[] buffer = new byte[100];
                        int written = req.writeBytesWireFormat(buffer, 0);
                        success[index] = (written == 4 && SMBUtil.readInt2(buffer, 0) == 4);
                    } catch (Exception e) {
                        success[index] = false;
                    }
                });
                threads[i].start();
            }

            for (Thread thread : threads) {
                thread.join();
            }

            for (boolean s : success) {
                assertTrue(s);
            }
        }
    }
}
