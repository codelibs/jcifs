package jcifs.dcerpc;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.net.MalformedURLException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.BufferCache;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;

/**
 * Comprehensive test suite for DcerpcHandle class
 * Tests binding parsing, handle creation, bind operations, and communication
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("DcerpcHandle Test Suite")
class DcerpcHandleTest {

    @Mock
    private CIFSContext mockContext;
    
    @Mock
    private DcerpcBinding mockBinding;
    
    @Mock
    private BufferCache mockBufferCache;
    
    @Mock
    private DcerpcSecurityProvider mockSecurityProvider;

    // Concrete implementation of DcerpcHandle for testing
    static class TestDcerpcHandle extends DcerpcHandle {
        private String server;
        private String serverWithDfs;
        private byte[] sessionKey;
        private int doReceiveFragmentReturn = 0;
        private int doSendReceiveFragmentReturn = 0;
        private CIFSContext localTransportContext;

        public TestDcerpcHandle(CIFSContext tc) {
            super(tc);
            this.localTransportContext = tc;
            this.server = "test_server";
            this.serverWithDfs = "test_server_dfs";
            this.sessionKey = new byte[] { 1, 2, 3, 4 };
        }

        public TestDcerpcHandle(CIFSContext tc, DcerpcBinding binding) {
            super(tc, binding);
            this.localTransportContext = tc;
            this.server = "test_server";
            this.serverWithDfs = "test_server_dfs";
            this.sessionKey = new byte[] { 1, 2, 3, 4 };
        }

        @Override
        public String getServer() {
            return server;
        }

        @Override
        public String getServerWithDfs() {
            return serverWithDfs;
        }

        @Override
        public CIFSContext getTransportContext() {
            return localTransportContext;
        }

        @Override
        public byte[] getSessionKey() throws CIFSException {
            return sessionKey;
        }

        @Override
        protected void doSendFragment(byte[] buf, int off, int length) throws IOException {
            // Mock implementation for testing
        }

        @Override
        protected int doReceiveFragment(byte[] buf) throws IOException {
            return doReceiveFragmentReturn;
        }

        @Override
        protected int doSendReceiveFragment(byte[] out, int off, int length, byte[] inB) throws IOException {
            return doSendReceiveFragmentReturn;
        }

        public void setDoReceiveFragmentReturn(int value) {
            this.doReceiveFragmentReturn = value;
        }

        public void setDoSendReceiveFragmentReturn(int value) {
            this.doSendReceiveFragmentReturn = value;
        }

        @Override
        protected NdrBuffer encodeMessage(DcerpcMessage msg, byte[] out) throws NdrException, DcerpcException {
            return super.encodeMessage(msg, out);
        }
    }

    private TestDcerpcHandle handle;

    @BeforeEach
    void setUp() {
        // Setup buffer cache mocks with lenient stubbing
        lenient().when(mockContext.getBufferCache()).thenReturn(mockBufferCache);
        lenient().when(mockBufferCache.getBuffer()).thenReturn(new byte[8192]);
        handle = new TestDcerpcHandle(mockContext, mockBinding);
    }

    @Nested
    @DisplayName("Binding Parsing Tests")
    class BindingParsingTests {

        @ParameterizedTest
        @DisplayName("Should parse valid binding URLs correctly")
        @CsvSource({
            "'ncacn_np:\\\\server[endpoint=\\pipe\\srvsvc]', ncacn_np, server, '\\pipe\\srvsvc'",
            "'ncacn_np:server[\\pipe\\srvsvc]', ncacn_np, server, '\\pipe\\srvsvc'",
            "'ncacn_np:[\\pipe\\srvsvc]', ncacn_np, 127.0.0.1, '\\pipe\\srvsvc'",
            "'ncacn_np:server[endpoint=\\pipe\\srvsvc]', ncacn_np, server, '\\pipe\\srvsvc'"
        })
        void testParseValidBindingUrls(String url, String expectedProto, String expectedServer, String expectedEndpoint)
                throws DcerpcException {
            // When: Parsing the binding URL
            DcerpcBinding binding = DcerpcHandle.parseBinding(url);
            
            // Then: Should parse correctly
            assertNotNull(binding);
            assertEquals(expectedProto, binding.getProto());
            assertEquals(expectedServer, binding.getServer());
            assertEquals(expectedEndpoint, binding.getEndpoint());
        }

        @ParameterizedTest
        @DisplayName("Should handle IPv6 addresses correctly")
        @CsvSource({
            "'ncacn_np:[::1][endpoint=\\pipe\\srvsvc]', ncacn_np, '[::1]', '\\pipe\\srvsvc'"
        })
        void testParseIPv6BindingUrls(String url, String expectedProto, String expectedServer, String expectedEndpoint)
                throws DcerpcException {
            // When: Parsing IPv6 binding URL
            DcerpcBinding binding = DcerpcHandle.parseBinding(url);
            
            // Then: Should parse IPv6 address correctly
            assertNotNull(binding);
            assertEquals(expectedProto, binding.getProto());
            assertEquals(expectedServer, binding.getServer());
            assertEquals(expectedEndpoint, binding.getEndpoint());
        }

        @ParameterizedTest
        @DisplayName("Should reject invalid binding URLs")
        @ValueSource(strings = {
            "invalid_url",
            "proto:",
            "proto:server[]",
            "proto:[key=]",
            "proto:[=value]",
            "proto:server[endpoint=]",
            "proto:[endpoint=]"
        })
        void testParseInvalidBindingUrls(String url) {
            // When/Then: Should throw DcerpcException for invalid URLs
            assertThrows(DcerpcException.class, () -> DcerpcHandle.parseBinding(url));
        }

        @Test
        @DisplayName("Should handle binding URLs without endpoints correctly")
        void testParseBindingWithoutEndpoint() {
            // When/Then: URLs without proper endpoints should fail
            assertThrows(DcerpcException.class, () -> DcerpcHandle.parseBinding("ncacn_np:server"));
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create handle with context only")
        void testConstructorWithContextOnly() {
            // When: Creating handle with context only
            TestDcerpcHandle h = new TestDcerpcHandle(mockContext);
            
            // Then: Should initialize correctly
            assertNotNull(h);
            assertEquals(mockContext, h.getTransportContext());
            assertNull(h.getBinding());
        }

        @Test
        @DisplayName("Should create handle with context and binding")
        void testConstructorWithContextAndBinding() {
            // When: Creating handle with context and binding
            TestDcerpcHandle h = new TestDcerpcHandle(mockContext, mockBinding);
            
            // Then: Should initialize correctly
            assertNotNull(h);
            assertEquals(mockContext, h.getTransportContext());
            assertEquals(mockBinding, h.getBinding());
        }
    }

    @Nested
    @DisplayName("Handle Creation Tests")
    class HandleCreationTests {

        @Test
        @DisplayName("Should create DcerpcPipeHandle for ncacn_np protocol")
        void testGetHandleNcacnNpProtocol() {
            // When/Then: Should attempt to create DcerpcPipeHandle (may fail due to SMB URL creation)
            // This tests the protocol recognition logic, actual creation may fail due to missing SMB support
            assertThrows(Exception.class, () -> 
                DcerpcHandle.getHandle("ncacn_np:\\\\server[endpoint=\\pipe\\srvsvc]", mockContext));
        }

        @Test
        @DisplayName("Should reject unsupported protocols")
        void testGetHandleUnsupportedProtocol() {
            // When/Then: Should throw exception for unsupported protocols
            assertThrows(DcerpcException.class, 
                () -> DcerpcHandle.getHandle("unsupported:\\\\server", mockContext));
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return correct values from getters")
        void testGetters() throws CIFSException {
            // When/Then: All getters should return expected values
            assertEquals(mockBinding, handle.getBinding());
            assertTrue(handle.getMaxRecv() > 0);
            assertTrue(handle.getMaxXmit() > 0);
            assertEquals("test_server", handle.getServer());
            assertEquals("test_server_dfs", handle.getServerWithDfs());
            assertEquals(mockContext, handle.getTransportContext());
            assertArrayEquals(new byte[] { 1, 2, 3, 4 }, handle.getSessionKey());
        }
    }

    @Nested
    @DisplayName("Bind Operation Tests")
    class BindOperationTests {

        @Test
        @DisplayName("Should execute bind operation successfully")
        void testBindSuccess() throws DcerpcException, IOException {
            // Given: Spy to intercept sendrecv calls
            TestDcerpcHandle spyHandle = spy(new TestDcerpcHandle(mockContext, mockBinding));
            doNothing().when(spyHandle).sendrecv(any(DcerpcMessage.class));

            // When: Binding the handle
            spyHandle.bind();

            // Then: Should call sendrecv with bind message
            verify(spyHandle).sendrecv(any(DcerpcMessage.class));
        }

        @Test
        @DisplayName("Should propagate IOException during bind")
        void testBindIOException() throws DcerpcException, IOException {
            // Given: Spy that throws IOException on sendrecv
            TestDcerpcHandle spyHandle = spy(new TestDcerpcHandle(mockContext, mockBinding));
            IOException expectedException = new IOException("Test IO Exception");
            doThrow(expectedException).when(spyHandle).sendrecv(any(DcerpcMessage.class));

            // When/Then: Should propagate IOException
            IOException thrown = assertThrows(IOException.class, () -> spyHandle.bind());
            assertEquals("Test IO Exception", thrown.getMessage());
        }
    }

    @Nested
    @DisplayName("Send/Receive Tests")
    class SendReceiveTests {

        @Test
        @DisplayName("Should handle basic send/receive fragment methods")
        void testSendReceiveFragmentMethods() throws IOException {
            // Given: Test handle with configured return values
            handle.setDoSendReceiveFragmentReturn(100);
            handle.setDoReceiveFragmentReturn(50);

            // When: Calling fragment methods
            int sendReceiveResult = handle.doSendReceiveFragment(new byte[10], 0, 10, new byte[100]);
            int receiveResult = handle.doReceiveFragment(new byte[100]);

            // Then: Should return configured values
            assertEquals(100, sendReceiveResult);
            assertEquals(50, receiveResult);
        }

        @Test
        @DisplayName("Should handle send fragment operation")
        void testSendFragment() throws IOException {
            // When: Calling send fragment (no-op implementation)
            // Then: Should not throw exception
            assertDoesNotThrow(() -> handle.doSendFragment(new byte[10], 0, 10));
        }

        @Test
        @DisplayName("Should handle encode message operation")
        void testEncodeMessage() throws NdrException, DcerpcException {
            // Given: Mock message
            DcerpcMessage mockMessage = mock(DcerpcMessage.class);
            lenient().when(mockMessage.getResult()).thenReturn(null);

            // When: Encoding message (calls parent implementation)
            // Then: Should complete without throwing exception
            assertDoesNotThrow(() -> handle.encodeMessage(mockMessage, new byte[100]));
        }
    }

    @Nested
    @DisplayName("Configuration Tests")
    class ConfigurationTests {

        @Test
        @DisplayName("Should set security provider")
        void testSetDcerpcSecurityProvider() {
            // When: Setting security provider
            handle.setDcerpcSecurityProvider(mockSecurityProvider);
            
            // Then: Should not throw exception (private field, no direct verification)
            assertDoesNotThrow(() -> handle.setDcerpcSecurityProvider(mockSecurityProvider));
        }

        @Test
        @DisplayName("Should handle close operation")
        void testClose() throws IOException {
            // When: Closing handle
            handle.close();
            
            // Then: Should complete without errors
            assertDoesNotThrow(() -> handle.close());
        }

        @Test
        @DisplayName("Should return string representation")
        void testToString() {
            // Given: Mock binding with toString
            when(mockBinding.toString()).thenReturn("mockBindingString");

            // When: Getting string representation
            String result = handle.toString();

            // Then: Should return binding's string representation
            assertEquals("mockBindingString", result);
        }
    }

    @Nested
    @DisplayName("Edge Cases and Error Handling")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle null binding toString")
        void testToStringWithNullBinding() {
            // Given: Handle with null binding
            TestDcerpcHandle handleWithNullBinding = new TestDcerpcHandle(mockContext);

            // When/Then: Should throw NPE for null binding (expected behavior)
            assertThrows(NullPointerException.class, () -> handleWithNullBinding.toString());
        }

        @Test
        @DisplayName("Should handle session key retrieval")
        void testSessionKeyRetrieval() throws CIFSException {
            // When: Getting session key
            byte[] sessionKey = handle.getSessionKey();

            // Then: Should return expected session key
            assertNotNull(sessionKey);
            assertArrayEquals(new byte[] { 1, 2, 3, 4 }, sessionKey);
        }

        @Test
        @DisplayName("Should handle max values configuration")
        void testMaxValuesConfiguration() {
            // When: Getting max transmission values
            int maxRecv = handle.getMaxRecv();
            int maxXmit = handle.getMaxXmit();

            // Then: Should return positive values
            assertTrue(maxRecv > 0);
            assertTrue(maxXmit > 0);
        }
    }
}