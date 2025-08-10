package jcifs.internal.smb2.create;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
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
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.internal.SMBProtocolDecodingException;

/**
 * Test class for CreateContextResponse interface functionality
 */
@DisplayName("CreateContextResponse Tests")
class CreateContextResponseTest {

    /**
     * Test implementation of CreateContextResponse for testing purposes
     */
    static class TestCreateContextResponse implements CreateContextResponse {
        private byte[] name;
        private byte[] data;
        private int decodeCallCount = 0;
        private boolean throwOnDecode = false;

        public TestCreateContextResponse(byte[] name) {
            this.name = name;
        }

        @Override
        public byte[] getName() {
            return name;
        }

        @Override
        public int decode(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException {
            decodeCallCount++;
            if (throwOnDecode) {
                throw new SMBProtocolDecodingException("Test decode error");
            }
            if (buffer == null) {
                throw new SMBProtocolDecodingException("Buffer cannot be null");
            }
            if (bufferIndex < 0 || len < 0) {
                throw new SMBProtocolDecodingException("Invalid buffer parameters");
            }
            if (bufferIndex + len > buffer.length) {
                throw new SMBProtocolDecodingException("Buffer overflow");
            }
            
            // Store the decoded data
            this.data = new byte[len];
            System.arraycopy(buffer, bufferIndex, this.data, 0, len);
            
            return len;
        }

        public byte[] getData() {
            return data;
        }

        public int getDecodeCallCount() {
            return decodeCallCount;
        }

        public void setThrowOnDecode(boolean throwOnDecode) {
            this.throwOnDecode = throwOnDecode;
        }
    }

    /**
     * Mock implementation for testing interface contract
     */
    static class MockCreateContextResponse implements CreateContextResponse {
        private final byte[] name;

        public MockCreateContextResponse(String name) {
            this.name = name != null ? name.getBytes(StandardCharsets.UTF_8) : null;
        }

        @Override
        public byte[] getName() {
            return name;
        }

        @Override
        public int decode(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException {
            return 0;
        }
    }

    @Nested
    @DisplayName("Interface Contract Tests")
    class InterfaceContractTests {

        @Test
        @DisplayName("Interface should be correctly implemented by mock")
        void testInterfaceImplementation() {
            CreateContextResponse response = mock(CreateContextResponse.class);
            assertNotNull(response);
            assertTrue(response instanceof CreateContextResponse);
        }

        @Test
        @DisplayName("getName() should return expected byte array")
        void testGetNameMethod() {
            byte[] expectedName = "TEST_CONTEXT".getBytes(StandardCharsets.UTF_8);
            CreateContextResponse response = mock(CreateContextResponse.class);
            when(response.getName()).thenReturn(expectedName);

            byte[] actualName = response.getName();
            assertArrayEquals(expectedName, actualName);
            verify(response, times(1)).getName();
        }

        @Test
        @DisplayName("getName() should handle null return value")
        void testGetNameWithNull() {
            CreateContextResponse response = mock(CreateContextResponse.class);
            when(response.getName()).thenReturn(null);

            byte[] actualName = response.getName();
            assertEquals(null, actualName);
        }

        @Test
        @DisplayName("decode() method should be callable")
        void testDecodeMethod() throws SMBProtocolDecodingException {
            CreateContextResponse response = mock(CreateContextResponse.class);
            byte[] buffer = new byte[100];
            when(response.decode(any(byte[].class), anyInt(), anyInt())).thenReturn(10);

            int result = response.decode(buffer, 0, 10);
            assertEquals(10, result);
            verify(response, times(1)).decode(buffer, 0, 10);
        }

        @Test
        @DisplayName("decode() should handle exceptions")
        void testDecodeWithException() throws SMBProtocolDecodingException {
            CreateContextResponse response = mock(CreateContextResponse.class);
            byte[] buffer = new byte[100];
            when(response.decode(any(byte[].class), anyInt(), anyInt()))
                .thenThrow(new SMBProtocolDecodingException("Test error"));

            assertThrows(SMBProtocolDecodingException.class, 
                () -> response.decode(buffer, 0, 10));
        }
    }

    @Nested
    @DisplayName("Test Implementation Tests")
    class TestImplementationTests {

        private TestCreateContextResponse testResponse;
        private byte[] testName;
        private byte[] testBuffer;

        @BeforeEach
        void setUp() {
            testName = "CREATE_CONTEXT_TEST".getBytes(StandardCharsets.UTF_8);
            testResponse = new TestCreateContextResponse(testName);
            testBuffer = new byte[256];
            Arrays.fill(testBuffer, (byte) 0x42);
        }

        @Test
        @DisplayName("Should correctly store and return name")
        void testNameStorage() {
            assertArrayEquals(testName, testResponse.getName());
        }

        @Test
        @DisplayName("Should handle null name")
        void testNullName() {
            TestCreateContextResponse nullNameResponse = new TestCreateContextResponse(null);
            assertEquals(null, nullNameResponse.getName());
        }

        @Test
        @DisplayName("Should decode data correctly")
        void testDecode() throws SMBProtocolDecodingException {
            int length = 50;
            int result = testResponse.decode(testBuffer, 10, length);

            assertEquals(length, result);
            assertEquals(1, testResponse.getDecodeCallCount());
            assertNotNull(testResponse.getData());
            assertEquals(length, testResponse.getData().length);
            
            // Verify data was copied correctly
            for (int i = 0; i < length; i++) {
                assertEquals(testBuffer[10 + i], testResponse.getData()[i]);
            }
        }

        @Test
        @DisplayName("Should throw exception on null buffer")
        void testDecodeWithNullBuffer() {
            assertThrows(SMBProtocolDecodingException.class,
                () -> testResponse.decode(null, 0, 10),
                "Should throw exception for null buffer");
        }

        @Test
        @DisplayName("Should throw exception on negative buffer index")
        void testDecodeWithNegativeIndex() {
            assertThrows(SMBProtocolDecodingException.class,
                () -> testResponse.decode(testBuffer, -1, 10),
                "Should throw exception for negative buffer index");
        }

        @Test
        @DisplayName("Should throw exception on negative length")
        void testDecodeWithNegativeLength() {
            assertThrows(SMBProtocolDecodingException.class,
                () -> testResponse.decode(testBuffer, 0, -1),
                "Should throw exception for negative length");
        }

        @Test
        @DisplayName("Should throw exception on buffer overflow")
        void testDecodeWithBufferOverflow() {
            assertThrows(SMBProtocolDecodingException.class,
                () -> testResponse.decode(testBuffer, 250, 10),
                "Should throw exception when reading beyond buffer bounds");
        }

        @Test
        @DisplayName("Should handle zero-length decode")
        void testDecodeWithZeroLength() throws SMBProtocolDecodingException {
            int result = testResponse.decode(testBuffer, 0, 0);
            
            assertEquals(0, result);
            assertNotNull(testResponse.getData());
            assertEquals(0, testResponse.getData().length);
        }

        @Test
        @DisplayName("Should count decode calls correctly")
        void testDecodeCallCount() throws SMBProtocolDecodingException {
            assertEquals(0, testResponse.getDecodeCallCount());
            
            testResponse.decode(testBuffer, 0, 10);
            assertEquals(1, testResponse.getDecodeCallCount());
            
            testResponse.decode(testBuffer, 20, 15);
            assertEquals(2, testResponse.getDecodeCallCount());
            
            testResponse.decode(testBuffer, 50, 20);
            assertEquals(3, testResponse.getDecodeCallCount());
        }

        @Test
        @DisplayName("Should throw configured exception on decode")
        void testConfiguredExceptionOnDecode() {
            testResponse.setThrowOnDecode(true);
            
            assertThrows(SMBProtocolDecodingException.class,
                () -> testResponse.decode(testBuffer, 0, 10),
                "Should throw configured exception");
        }

        @ParameterizedTest
        @ValueSource(ints = {1, 10, 50, 100, 255})
        @DisplayName("Should handle various data lengths")
        void testVariousDataLengths(int length) throws SMBProtocolDecodingException {
            int result = testResponse.decode(testBuffer, 0, length);
            
            assertEquals(length, result);
            assertNotNull(testResponse.getData());
            assertEquals(length, testResponse.getData().length);
        }
    }

    @Nested
    @DisplayName("Mock Implementation Tests")
    class MockImplementationTests {

        @Test
        @DisplayName("Should create mock with string name")
        void testMockWithStringName() {
            String nameStr = "MOCK_CONTEXT";
            MockCreateContextResponse mock = new MockCreateContextResponse(nameStr);
            
            assertArrayEquals(nameStr.getBytes(StandardCharsets.UTF_8), mock.getName());
        }

        @Test
        @DisplayName("Should handle null string name")
        void testMockWithNullStringName() {
            MockCreateContextResponse mock = new MockCreateContextResponse(null);
            assertEquals(null, mock.getName());
        }

        @Test
        @DisplayName("Should return zero from decode")
        void testMockDecode() throws SMBProtocolDecodingException {
            MockCreateContextResponse mock = new MockCreateContextResponse("TEST");
            byte[] buffer = new byte[100];
            
            int result = mock.decode(buffer, 0, 50);
            assertEquals(0, result);
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "SHORT", "VERY_LONG_CONTEXT_NAME_FOR_TESTING", "特殊字符"})
        @DisplayName("Should handle various name strings")
        void testVariousNameStrings(String name) {
            MockCreateContextResponse mock = new MockCreateContextResponse(name);
            assertArrayEquals(name.getBytes(StandardCharsets.UTF_8), mock.getName());
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle large buffer decoding")
        void testLargeBufferDecode() throws SMBProtocolDecodingException {
            byte[] largeBuffer = new byte[65536];
            Arrays.fill(largeBuffer, (byte) 0xFF);
            
            TestCreateContextResponse response = new TestCreateContextResponse(
                "LARGE_BUFFER_TEST".getBytes(StandardCharsets.UTF_8));
            
            int result = response.decode(largeBuffer, 1000, 5000);
            assertEquals(5000, result);
            assertEquals(5000, response.getData().length);
        }

        @Test
        @DisplayName("Should handle empty name array")
        void testEmptyNameArray() {
            byte[] emptyName = new byte[0];
            TestCreateContextResponse response = new TestCreateContextResponse(emptyName);
            
            assertNotNull(response.getName());
            assertEquals(0, response.getName().length);
        }

        @Test
        @DisplayName("Should handle boundary conditions in decode")
        void testBoundaryConditions() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[100];
            TestCreateContextResponse response = new TestCreateContextResponse(
                "BOUNDARY".getBytes(StandardCharsets.UTF_8));
            
            // Test at buffer start
            int result1 = response.decode(buffer, 0, 10);
            assertEquals(10, result1);
            
            // Test at buffer end
            int result2 = response.decode(buffer, 90, 10);
            assertEquals(10, result2);
            
            // Test full buffer
            int result3 = response.decode(buffer, 0, 100);
            assertEquals(100, result3);
        }

        @Test
        @DisplayName("Should handle concurrent decode calls")
        void testConcurrentDecoding() throws SMBProtocolDecodingException {
            TestCreateContextResponse response = new TestCreateContextResponse(
                "CONCURRENT".getBytes(StandardCharsets.UTF_8));
            byte[] buffer1 = new byte[100];
            byte[] buffer2 = new byte[200];
            
            Arrays.fill(buffer1, (byte) 0x11);
            Arrays.fill(buffer2, (byte) 0x22);
            
            // First decode
            response.decode(buffer1, 0, 50);
            byte[] data1 = response.getData();
            
            // Second decode should overwrite
            response.decode(buffer2, 10, 60);
            byte[] data2 = response.getData();
            
            // Verify second decode overwrote first
            assertEquals(60, data2.length);
            assertEquals((byte) 0x22, data2[0]);
        }
    }

    @Nested
    @DisplayName("Integration Pattern Tests")
    class IntegrationPatternTests {

        @Test
        @DisplayName("Should simulate usage in Smb2CreateResponse context")
        void testSimulatedUsagePattern() throws SMBProtocolDecodingException {
            // Simulate the pattern from Smb2CreateResponse
            byte[] nameBytes = "SMB2_CREATE_CONTEXT".getBytes(StandardCharsets.UTF_8);
            byte[] dataBuffer = new byte[1024];
            Arrays.fill(dataBuffer, (byte) 0xAB);
            
            TestCreateContextResponse contextResponse = new TestCreateContextResponse(nameBytes);
            
            // Simulate decode call
            int dataOffset = 100;
            int dataLength = 200;
            contextResponse.decode(dataBuffer, dataOffset, dataLength);
            
            // Verify
            assertArrayEquals(nameBytes, contextResponse.getName());
            assertEquals(dataLength, contextResponse.getData().length);
            
            // Verify data content
            for (int i = 0; i < dataLength; i++) {
                assertEquals(dataBuffer[dataOffset + i], contextResponse.getData()[i]);
            }
        }

        @Test
        @DisplayName("Should handle array of context responses")
        void testArrayOfContextResponses() throws SMBProtocolDecodingException {
            CreateContextResponse[] contexts = new CreateContextResponse[3];
            byte[] buffer = new byte[300];
            
            contexts[0] = new TestCreateContextResponse("CONTEXT1".getBytes(StandardCharsets.UTF_8));
            contexts[1] = new TestCreateContextResponse("CONTEXT2".getBytes(StandardCharsets.UTF_8));
            contexts[2] = new TestCreateContextResponse("CONTEXT3".getBytes(StandardCharsets.UTF_8));
            
            // Decode each context
            for (int i = 0; i < contexts.length; i++) {
                contexts[i].decode(buffer, i * 100, 50);
            }
            
            // Verify each context
            for (int i = 0; i < contexts.length; i++) {
                assertNotNull(contexts[i].getName());
                assertTrue(contexts[i].getName().length > 0);
            }
        }
    }
}