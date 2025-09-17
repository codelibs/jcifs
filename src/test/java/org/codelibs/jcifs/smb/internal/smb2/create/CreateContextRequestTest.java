package org.codelibs.jcifs.smb.internal.smb2.create;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Test class for CreateContextRequest interface
 */
@DisplayName("CreateContextRequest Tests")
class CreateContextRequestTest {

    /**
     * Test implementation of CreateContextRequest for testing purposes
     */
    static class TestCreateContextRequest implements CreateContextRequest {
        private byte[] name;
        private byte[] data;
        private int encodedSize;
        private boolean throwOnEncode = false;
        private boolean throwOnSize = false;
        private int sizeCallCount = 0;
        private int encodeCallCount = 0;

        public TestCreateContextRequest(byte[] name) {
            this.name = name;
            this.encodedSize = name != null ? name.length + 16 : 16; // 16 bytes for header
        }

        public TestCreateContextRequest(byte[] name, byte[] data) {
            this.name = name;
            this.data = data;
            this.encodedSize = (name != null ? name.length : 0) + (data != null ? data.length : 0) + 16;
        }

        @Override
        public byte[] getName() {
            return name;
        }

        @Override
        public int encode(byte[] dst, int dstIndex) {
            encodeCallCount++;
            if (throwOnEncode) {
                throw new RuntimeException("Test encode error");
            }
            if (dst == null) {
                throw new IllegalArgumentException("Destination buffer cannot be null");
            }
            if (dstIndex < 0) {
                throw new IllegalArgumentException("Destination index cannot be negative");
            }
            if (dstIndex + encodedSize > dst.length) {
                throw new ArrayIndexOutOfBoundsException("Buffer overflow");
            }

            // Simulate encoding: write header (8 bytes)
            Arrays.fill(dst, dstIndex, dstIndex + 8, (byte) 0xFF);
            int offset = dstIndex + 8;

            // Write name if present
            if (name != null && name.length > 0) {
                System.arraycopy(name, 0, dst, offset, name.length);
                offset += name.length;
            }

            // Write data if present
            if (data != null && data.length > 0) {
                System.arraycopy(data, 0, dst, offset, data.length);
                offset += data.length;
            }

            // Pad to 8-byte boundary
            while ((offset - dstIndex) % 8 != 0) {
                dst[offset++] = 0;
            }

            return offset - dstIndex;
        }

        @Override
        public int size() {
            sizeCallCount++;
            if (throwOnSize) {
                throw new RuntimeException("Test size error");
            }
            return encodedSize;
        }

        public void setEncodedSize(int size) {
            this.encodedSize = size;
        }

        public void setThrowOnEncode(boolean throwOnEncode) {
            this.throwOnEncode = throwOnEncode;
        }

        public void setThrowOnSize(boolean throwOnSize) {
            this.throwOnSize = throwOnSize;
        }

        public int getSizeCallCount() {
            return sizeCallCount;
        }

        public int getEncodeCallCount() {
            return encodeCallCount;
        }

        public byte[] getData() {
            return data;
        }
    }

    /**
     * Mock implementation for basic interface testing
     */
    static class MockCreateContextRequest implements CreateContextRequest {
        private final byte[] name;
        private final int size;

        public MockCreateContextRequest(String name) {
            this(name, 32);
        }

        public MockCreateContextRequest(String name, int size) {
            this.name = name != null ? name.getBytes(StandardCharsets.UTF_8) : null;
            this.size = size;
        }

        @Override
        public byte[] getName() {
            return name;
        }

        @Override
        public int encode(byte[] dst, int dstIndex) {
            return size;
        }

        @Override
        public int size() {
            return size;
        }
    }

    @Nested
    @DisplayName("Interface Contract Tests")
    class InterfaceContractTests {

        @Test
        @DisplayName("Interface should be correctly implemented by mock")
        void testInterfaceImplementation() {
            CreateContextRequest request = mock(CreateContextRequest.class);
            assertNotNull(request);
            assertTrue(request instanceof CreateContextRequest);
        }

        @Test
        @DisplayName("getName() should return expected byte array")
        void testGetNameMethod() {
            byte[] expectedName = "TEST_CONTEXT".getBytes(StandardCharsets.UTF_8);
            CreateContextRequest request = mock(CreateContextRequest.class);
            when(request.getName()).thenReturn(expectedName);

            byte[] actualName = request.getName();
            assertArrayEquals(expectedName, actualName);
            verify(request, times(1)).getName();
        }

        @Test
        @DisplayName("getName() should handle null return value")
        void testGetNameWithNull() {
            CreateContextRequest request = mock(CreateContextRequest.class);
            when(request.getName()).thenReturn(null);

            byte[] actualName = request.getName();
            assertNull(actualName);
        }

        @Test
        @DisplayName("encode() method should be callable")
        void testEncodeMethod() {
            CreateContextRequest request = mock(CreateContextRequest.class);
            byte[] buffer = new byte[100];
            when(request.encode(any(byte[].class), anyInt())).thenReturn(16);

            int result = request.encode(buffer, 0);
            assertEquals(16, result);
            verify(request, times(1)).encode(buffer, 0);
        }

        @Test
        @DisplayName("size() method should return correct size")
        void testSizeMethod() {
            CreateContextRequest request = mock(CreateContextRequest.class);
            when(request.size()).thenReturn(64);

            int size = request.size();
            assertEquals(64, size);
            verify(request, times(1)).size();
        }

        @Test
        @DisplayName("encode() should handle exceptions")
        void testEncodeWithException() {
            CreateContextRequest request = mock(CreateContextRequest.class);
            byte[] buffer = new byte[100];
            when(request.encode(any(byte[].class), anyInt())).thenThrow(new RuntimeException("Test error"));

            assertThrows(RuntimeException.class, () -> request.encode(buffer, 0));
        }
    }

    @Nested
    @DisplayName("Test Implementation Tests")
    class TestImplementationTests {

        private TestCreateContextRequest testRequest;
        private byte[] testName;
        private byte[] testBuffer;

        @BeforeEach
        void setUp() {
            testName = "CREATE_REQUEST_TEST".getBytes(StandardCharsets.UTF_8);
            testRequest = new TestCreateContextRequest(testName);
            testBuffer = new byte[256];
        }

        @Test
        @DisplayName("Should correctly store and return name")
        void testNameStorage() {
            assertArrayEquals(testName, testRequest.getName());
        }

        @Test
        @DisplayName("Should handle null name")
        void testNullName() {
            TestCreateContextRequest nullNameRequest = new TestCreateContextRequest(null);
            assertNull(nullNameRequest.getName());
        }

        @Test
        @DisplayName("Should encode data correctly")
        void testEncode() {
            int result = testRequest.encode(testBuffer, 10);

            assertTrue(result > 0);
            assertEquals(1, testRequest.getEncodeCallCount());

            // Verify header was written
            for (int i = 10; i < 18; i++) {
                assertEquals((byte) 0xFF, testBuffer[i]);
            }
        }

        @Test
        @DisplayName("Should encode with data correctly")
        void testEncodeWithData() {
            byte[] data = "CONTEXT_DATA".getBytes(StandardCharsets.UTF_8);
            TestCreateContextRequest requestWithData = new TestCreateContextRequest(testName, data);

            int result = requestWithData.encode(testBuffer, 0);
            assertTrue(result > 0);

            // Verify header
            for (int i = 0; i < 8; i++) {
                assertEquals((byte) 0xFF, testBuffer[i]);
            }

            // Verify name was copied
            byte[] nameCheck = new byte[testName.length];
            System.arraycopy(testBuffer, 8, nameCheck, 0, testName.length);
            assertArrayEquals(testName, nameCheck);
        }

        @Test
        @DisplayName("Should return correct size")
        void testSize() {
            int size = testRequest.size();
            assertTrue(size > 0);
            assertEquals(testName.length + 16, size);
            assertEquals(1, testRequest.getSizeCallCount());
        }

        @Test
        @DisplayName("Should allow size override")
        void testSizeOverride() {
            testRequest.setEncodedSize(128);
            assertEquals(128, testRequest.size());
        }

        @Test
        @DisplayName("Should throw exception on null buffer")
        void testEncodeWithNullBuffer() {
            assertThrows(IllegalArgumentException.class, () -> testRequest.encode(null, 0), "Should throw exception for null buffer");
        }

        @Test
        @DisplayName("Should throw exception on negative index")
        void testEncodeWithNegativeIndex() {
            assertThrows(IllegalArgumentException.class, () -> testRequest.encode(testBuffer, -1),
                    "Should throw exception for negative index");
        }

        @Test
        @DisplayName("Should throw exception on buffer overflow")
        void testEncodeWithBufferOverflow() {
            byte[] smallBuffer = new byte[10];
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> testRequest.encode(smallBuffer, 5),
                    "Should throw exception when buffer is too small");
        }

        @Test
        @DisplayName("Should handle zero-length name")
        void testZeroLengthName() {
            TestCreateContextRequest emptyNameRequest = new TestCreateContextRequest(new byte[0]);

            assertNotNull(emptyNameRequest.getName());
            assertEquals(0, emptyNameRequest.getName().length);

            int result = emptyNameRequest.encode(testBuffer, 0);
            assertTrue(result >= 8); // At least header size
        }

        @Test
        @DisplayName("Should count method calls correctly")
        void testMethodCallCounting() {
            assertEquals(0, testRequest.getSizeCallCount());
            assertEquals(0, testRequest.getEncodeCallCount());

            testRequest.size();
            assertEquals(1, testRequest.getSizeCallCount());

            testRequest.encode(testBuffer, 0);
            assertEquals(1, testRequest.getEncodeCallCount());

            testRequest.size();
            testRequest.size();
            assertEquals(3, testRequest.getSizeCallCount());

            testRequest.encode(testBuffer, 50);
            assertEquals(2, testRequest.getEncodeCallCount());
        }

        @Test
        @DisplayName("Should throw configured exception on encode")
        void testConfiguredExceptionOnEncode() {
            testRequest.setThrowOnEncode(true);

            assertThrows(RuntimeException.class, () -> testRequest.encode(testBuffer, 0), "Should throw configured exception");
        }

        @Test
        @DisplayName("Should throw configured exception on size")
        void testConfiguredExceptionOnSize() {
            testRequest.setThrowOnSize(true);

            assertThrows(RuntimeException.class, () -> testRequest.size(), "Should throw configured exception");
        }

        @Test
        @DisplayName("Should align to 8-byte boundary")
        void testPaddingAlignment() {
            // Test various name lengths to ensure proper padding
            for (int nameLen = 1; nameLen <= 32; nameLen++) {
                byte[] name = new byte[nameLen];
                Arrays.fill(name, (byte) 'A');
                TestCreateContextRequest req = new TestCreateContextRequest(name);

                byte[] buffer = new byte[256];
                int encodedSize = req.encode(buffer, 0);

                // Verify 8-byte alignment
                assertEquals(0, encodedSize % 8, "Encoded size should be 8-byte aligned for name length " + nameLen);
            }
        }

        @ParameterizedTest
        @ValueSource(ints = { 0, 10, 50, 100, 200 })
        @DisplayName("Should handle various buffer offsets")
        void testVariousBufferOffsets(int offset) {
            byte[] largeBuffer = new byte[512];
            int result = testRequest.encode(largeBuffer, offset);

            assertTrue(result > 0);
            // Verify header at correct offset
            for (int i = offset; i < offset + 8; i++) {
                assertEquals((byte) 0xFF, largeBuffer[i]);
            }
        }
    }

    @Nested
    @DisplayName("Mock Implementation Tests")
    class MockImplementationTests {

        @Test
        @DisplayName("Should create mock with string name")
        void testMockWithStringName() {
            String nameStr = "MOCK_CONTEXT";
            MockCreateContextRequest mock = new MockCreateContextRequest(nameStr);

            assertArrayEquals(nameStr.getBytes(StandardCharsets.UTF_8), mock.getName());
            assertEquals(32, mock.size());
        }

        @Test
        @DisplayName("Should handle null string name")
        void testMockWithNullStringName() {
            MockCreateContextRequest mock = new MockCreateContextRequest(null);
            assertNull(mock.getName());
        }

        @Test
        @DisplayName("Should return configured size from encode")
        void testMockEncode() {
            MockCreateContextRequest mock = new MockCreateContextRequest("TEST", 64);
            byte[] buffer = new byte[100];

            int result = mock.encode(buffer, 0);
            assertEquals(64, result);
            assertEquals(64, mock.size());
        }

        @ParameterizedTest
        @ValueSource(strings = { "", "SHORT", "VERY_LONG_CONTEXT_NAME_FOR_TESTING", "特殊字符" })
        @DisplayName("Should handle various name strings")
        void testVariousNameStrings(String name) {
            MockCreateContextRequest mock = new MockCreateContextRequest(name);
            assertArrayEquals(name.getBytes(StandardCharsets.UTF_8), mock.getName());
        }

        @ParameterizedTest
        @ValueSource(ints = { 8, 16, 32, 64, 128, 256 })
        @DisplayName("Should handle various sizes")
        void testVariousSizes(int size) {
            MockCreateContextRequest mock = new MockCreateContextRequest("TEST", size);
            assertEquals(size, mock.size());
            assertEquals(size, mock.encode(new byte[size * 2], 0));
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle large buffer encoding")
        void testLargeBufferEncode() {
            byte[] largeName = new byte[1024];
            Arrays.fill(largeName, (byte) 'X');
            byte[] largeData = new byte[2048];
            Arrays.fill(largeData, (byte) 'Y');

            TestCreateContextRequest request = new TestCreateContextRequest(largeName, largeData);

            byte[] buffer = new byte[8192];
            int result = request.encode(buffer, 100);

            assertTrue(result > 0);
            assertTrue(result <= buffer.length - 100);
        }

        @Test
        @DisplayName("Should handle empty data array")
        void testEmptyDataArray() {
            byte[] emptyData = new byte[0];
            byte[] name = "TEST_DATA".getBytes(StandardCharsets.UTF_8);
            TestCreateContextRequest request = new TestCreateContextRequest(name, emptyData);

            assertNotNull(request.getData());
            assertEquals(0, request.getData().length);
        }

        @Test
        @DisplayName("Should handle boundary conditions in encode")
        void testBoundaryConditions() {
            byte[] buffer = new byte[256];
            byte[] name = "BOUNDARY".getBytes(StandardCharsets.UTF_8);
            TestCreateContextRequest request = new TestCreateContextRequest(name);

            // Test at buffer start
            int result1 = request.encode(buffer, 0);
            assertTrue(result1 > 0);

            // Test at buffer middle
            int result2 = request.encode(buffer, 128);
            assertTrue(result2 > 0);

            // Test near buffer end (should still fit)
            request.setEncodedSize(16);
            int result3 = request.encode(buffer, 240);
            assertEquals(16, result3);
        }

        @Test
        @DisplayName("Should handle maximum name length")
        void testMaximumNameLength() {
            byte[] maxName = new byte[65536]; // 64KB
            Arrays.fill(maxName, (byte) 'M');
            TestCreateContextRequest request = new TestCreateContextRequest(maxName);

            assertArrayEquals(maxName, request.getName());
            assertTrue(request.size() > maxName.length);
        }

        @Test
        @DisplayName("Should handle concurrent encoding")
        void testConcurrentEncoding() {
            TestCreateContextRequest request = new TestCreateContextRequest("CONCURRENT".getBytes(StandardCharsets.UTF_8));

            byte[] buffer1 = new byte[256];
            byte[] buffer2 = new byte[256];

            // Encode to different buffers
            int result1 = request.encode(buffer1, 0);
            int result2 = request.encode(buffer2, 50);

            // Both should succeed independently
            assertTrue(result1 > 0);
            assertTrue(result2 > 0);

            // Verify headers in both buffers
            for (int i = 0; i < 8; i++) {
                assertEquals((byte) 0xFF, buffer1[i]);
                assertEquals((byte) 0xFF, buffer2[50 + i]);
            }
        }
    }

    @Nested
    @DisplayName("Integration Pattern Tests")
    class IntegrationPatternTests {

        @Test
        @DisplayName("Should simulate usage in Smb2CreateRequest context")
        void testSimulatedUsagePattern() {
            // Simulate the pattern from Smb2CreateRequest
            CreateContextRequest[] contexts = new CreateContextRequest[3];
            contexts[0] = new TestCreateContextRequest("CONTEXT1".getBytes(StandardCharsets.UTF_8));
            contexts[1] = new TestCreateContextRequest("CONTEXT2".getBytes(StandardCharsets.UTF_8));
            contexts[2] = new TestCreateContextRequest("CONTEXT3".getBytes(StandardCharsets.UTF_8));

            // Encode all contexts
            byte[] buffer = new byte[512];
            int offset = 0;
            for (CreateContextRequest context : contexts) {
                int encoded = context.encode(buffer, offset);
                assertTrue(encoded > 0);
                offset += encoded;
            }

            // Verify each context was encoded
            assertTrue(offset > 0);
            // The actual encoded size might be different from size() due to padding
            // Just verify that we encoded something for each context
            for (CreateContextRequest context : contexts) {
                assertNotNull(context.getName());
            }
        }

        @Test
        @DisplayName("Should handle array of context requests with varying sizes")
        void testArrayOfContextRequestsWithVaryingSizes() {
            CreateContextRequest[] contexts = new CreateContextRequest[] { new MockCreateContextRequest("SHORT", 16),
                    new MockCreateContextRequest("MEDIUM_LENGTH_NAME", 32),
                    new MockCreateContextRequest("VERY_LONG_CONTEXT_NAME_FOR_TESTING", 64) };

            byte[] buffer = new byte[512];
            int offset = 0;

            for (CreateContextRequest context : contexts) {
                assertNotNull(context.getName());
                int size = context.size();
                int encoded = context.encode(buffer, offset);
                assertEquals(size, encoded);
                offset += encoded;
            }

            // Verify total offset
            assertEquals(16 + 32 + 64, offset);
        }

        @Test
        @DisplayName("Should handle null context in array")
        void testNullContextInArray() {
            CreateContextRequest[] contexts = new CreateContextRequest[4];
            contexts[0] = new MockCreateContextRequest("FIRST");
            contexts[1] = null; // Null context
            contexts[2] = new MockCreateContextRequest("THIRD");
            contexts[3] = new MockCreateContextRequest("FOURTH");

            byte[] buffer = new byte[256];
            int offset = 0;
            int validCount = 0;

            for (CreateContextRequest context : contexts) {
                if (context != null) {
                    offset += context.encode(buffer, offset);
                    validCount++;
                }
            }

            assertEquals(3, validCount);
            assertTrue(offset > 0);
        }

        @Test
        @DisplayName("Should calculate combined size for multiple contexts")
        void testCombinedSizeCalculation() {
            CreateContextRequest[] contexts = new CreateContextRequest[5];
            int[] expectedSizes = { 16, 24, 32, 40, 48 };

            for (int i = 0; i < contexts.length; i++) {
                contexts[i] = new MockCreateContextRequest("CTX" + i, expectedSizes[i]);
            }

            // Calculate total size
            int totalSize = 0;
            for (int i = 0; i < contexts.length; i++) {
                assertEquals(expectedSizes[i], contexts[i].size());
                totalSize += contexts[i].size();
            }

            assertEquals(160, totalSize); // 16+24+32+40+48
        }

        @Test
        @DisplayName("Should handle special SMB2 context names")
        void testSMB2ContextNames() {
            // Common SMB2 create context names
            String[] contextNames = { "DHnQ", // Durable handle request
                    "DHnC", // Durable handle reconnect
                    "AlSi", // Allocation size
                    "MxAc", // Max access
                    "TWrp", // Timewarp
                    "QFid", // Query on disk ID
                    "RqLs", // Request lease
                    "DH2Q", // Durable handle request V2
                    "DH2C", // Durable handle reconnect V2
                    "ExtA", // Extended attributes
                    "SecD", // Security descriptor
                    "AppI" // App instance ID
            };

            for (String name : contextNames) {
                MockCreateContextRequest context = new MockCreateContextRequest(name);
                assertNotNull(context.getName());
                assertEquals(4, context.getName().length); // Most SMB2 context names are 4 bytes
                assertArrayEquals(name.getBytes(StandardCharsets.UTF_8), context.getName());
            }
        }
    }

    @Nested
    @DisplayName("Performance Tests")
    class PerformanceTests {

        @Test
        @DisplayName("Should handle repeated encoding efficiently")
        void testRepeatedEncoding() {
            TestCreateContextRequest request = new TestCreateContextRequest("PERFORMANCE".getBytes(StandardCharsets.UTF_8));
            byte[] buffer = new byte[256];

            // Encode multiple times
            for (int i = 0; i < 1000; i++) {
                int result = request.encode(buffer, 0);
                assertTrue(result > 0);
            }

            assertEquals(1000, request.getEncodeCallCount());
        }

        @Test
        @DisplayName("Should handle repeated size calls efficiently")
        void testRepeatedSizeCalls() {
            TestCreateContextRequest request = new TestCreateContextRequest("SIZE_TEST".getBytes(StandardCharsets.UTF_8));

            int expectedSize = request.size();

            // Call size multiple times
            for (int i = 0; i < 1000; i++) {
                assertEquals(expectedSize, request.size());
            }

            assertEquals(1001, request.getSizeCallCount()); // Including initial call
        }
    }
}