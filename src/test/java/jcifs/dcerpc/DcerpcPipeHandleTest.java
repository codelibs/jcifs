package jcifs.dcerpc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.BufferCache;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SmbPipeHandle;
import jcifs.SmbPipeResource;
import jcifs.SmbResourceLocator;
import jcifs.smb.SmbNamedPipe;
import jcifs.smb.SmbPipeHandleInternal;
import jcifs.util.Encdec;

/**
 * Test class for DcerpcPipeHandle
 */
@ExtendWith(MockitoExtension.class)
class DcerpcPipeHandleTest {

    @Mock
    private CIFSContext mockContext;
    @Mock
    private SmbNamedPipe mockSmbNamedPipe;
    @Mock
    private SmbPipeHandleInternal mockSmbPipeHandleInternal;
    @Mock
    private DcerpcBinding mockDcerpcBinding;
    @Mock
    private SmbResourceLocator mockSmbResourceLocator;
    @Mock
    private SmbPipeHandle mockSmbPipeHandle;
    @Mock
    private BufferCache mockBufferCache;

    private static final String TEST_URL = "ncacn_np:server[\\pipe\\test]";
    private static final String TEST_SERVER = "server";
    private static final String TEST_ENDPOINT = "\\pipe\\test";

    @BeforeEach
    void setUp() throws IOException {
        // Setup mock behavior with lenient stubbing to avoid UnnecessaryStubbingException
        lenient().when(mockSmbNamedPipe.openPipe()).thenReturn(mockSmbPipeHandle);
        lenient().when(mockSmbPipeHandle.unwrap(SmbPipeHandleInternal.class)).thenReturn(mockSmbPipeHandleInternal);
        lenient().when(mockSmbNamedPipe.getContext()).thenReturn(mockContext);
        lenient().when(mockSmbNamedPipe.getLocator()).thenReturn(mockSmbResourceLocator);
        lenient().when(mockDcerpcBinding.getServer()).thenReturn(TEST_SERVER);
        lenient().when(mockDcerpcBinding.getEndpoint()).thenReturn(TEST_ENDPOINT);
        lenient().when(mockContext.getBufferCache()).thenReturn(mockBufferCache);
        
        // Setup buffer cache to return buffers for sendrecv operations
        lenient().when(mockBufferCache.getBuffer()).thenReturn(new byte[8192]);
    }

    /**
     * Helper method to create a DcerpcPipeHandle with injected mocks
     * Uses mock to avoid constructor issues while allowing real method calls
     */
    private DcerpcPipeHandle createMockedDcerpcPipeHandle() throws Exception {
        // Create a mock without calling the constructor
        DcerpcPipeHandle handle = mock(DcerpcPipeHandle.class);
        
        // Inject the binding using reflection
        Field bindingField = DcerpcHandle.class.getDeclaredField("binding");
        bindingField.setAccessible(true);
        bindingField.set(handle, mockDcerpcBinding);
        
        // Inject the CIFSContext using reflection
        Field tcField = DcerpcHandle.class.getDeclaredField("transportContext");
        tcField.setAccessible(true);
        tcField.set(handle, mockContext);

        // Set max_recv field using reflection (default is 4280 in parent class)
        Field maxRecvField = DcerpcHandle.class.getDeclaredField("max_recv");
        maxRecvField.setAccessible(true);
        maxRecvField.set(handle, 4280);

        // Inject mocks using reflection
        Field pipeField = DcerpcPipeHandle.class.getDeclaredField("pipe");
        pipeField.setAccessible(true);
        pipeField.set(handle, mockSmbNamedPipe);

        Field handleField = DcerpcPipeHandle.class.getDeclaredField("handle");
        handleField.setAccessible(true);
        handleField.set(handle, mockSmbPipeHandleInternal);

        // Setup real method calls for the methods we want to test
        when(handle.getTransportContext()).thenCallRealMethod();
        when(handle.getServer()).thenCallRealMethod();
        when(handle.getServerWithDfs()).thenCallRealMethod();
        when(handle.getSessionKey()).thenCallRealMethod();
        when(handle.getBinding()).thenReturn(mockDcerpcBinding);
        doCallRealMethod().when(handle).doSendReceiveFragment(any(byte[].class), anyInt(), anyInt(), any(byte[].class));
        doCallRealMethod().when(handle).doSendFragment(any(byte[].class), anyInt(), anyInt());
        doCallRealMethod().when(handle).doReceiveFragment(any(byte[].class));
        doCallRealMethod().when(handle).close();
        
        // Add getMaxRecv() to return correct value
        lenient().when(handle.getMaxRecv()).thenReturn(4280);

        return handle;
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should throw DcerpcException for invalid URL format")
        void testConstructor_InvalidUrl() {
            String invalidUrl = "invalid:server";
            assertThrows(DcerpcException.class, 
                () -> new DcerpcPipeHandle(invalidUrl, mockContext, false),
                "Should throw DcerpcException for invalid protocol");
        }

        @Test
        @DisplayName("Should throw DcerpcException for missing endpoint")
        void testConstructor_MissingEndpoint() {
            String urlWithoutEndpoint = "ncacn_np:server";
            assertThrows(DcerpcException.class,
                () -> new DcerpcPipeHandle(urlWithoutEndpoint, mockContext, false),
                "Should throw DcerpcException for missing endpoint");
        }
    }

    @Nested
    @DisplayName("Getter Method Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return correct transport context")
        void testGetTransportContext() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            assertEquals(mockContext, handle.getTransportContext());
        }

        @Test
        @DisplayName("Should return correct server name")
        void testGetServer() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            when(mockSmbResourceLocator.getServer()).thenReturn("testServer");
            assertEquals("testServer", handle.getServer());
        }

        @Test
        @DisplayName("Should return correct server name with DFS")
        void testGetServerWithDfs() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            when(mockSmbResourceLocator.getServerWithDfs()).thenReturn("testServerDfs");
            assertEquals("testServerDfs", handle.getServerWithDfs());
        }

        @Test
        @DisplayName("Should return session key successfully")
        void testGetSessionKey() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            byte[] expectedKey = "sessionKey".getBytes();
            when(mockSmbPipeHandleInternal.getSessionKey()).thenReturn(expectedKey);
            assertArrayEquals(expectedKey, handle.getSessionKey());
        }

        @Test
        @DisplayName("Should propagate CIFSException when getting session key")
        void testGetSessionKey_ThrowsCIFSException() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            CIFSException exception = new CIFSException("Test exception");
            when(mockSmbPipeHandleInternal.getSessionKey()).thenThrow(exception);
            assertThrows(CIFSException.class, handle::getSessionKey);
        }
    }

    @Nested
    @DisplayName("Send/Receive Fragment Tests")
    class SendReceiveFragmentTests {

        @Test
        @DisplayName("Should send and receive fragment successfully")
        void testDoSendReceiveFragment_Success() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            
            byte[] buf = new byte[50];
            byte[] inB = new byte[100];
            
            // Setup fragment length in response buffer
            Encdec.enc_uint16le((short) 40, inB, 8);
            
            when(mockSmbPipeHandleInternal.isStale()).thenReturn(false);
            when(mockSmbPipeHandleInternal.sendrecv(buf, 0, 50, inB, 4280)).thenReturn(40);
            
            int result = handle.doSendReceiveFragment(buf, 0, 50, inB);
            assertEquals(40, result);
            verify(mockSmbPipeHandleInternal).sendrecv(buf, 0, 50, inB, 4280);
        }

        @Test
        @DisplayName("Should handle multiple receives for fragment")
        void testDoSendReceiveFragment_MultipleReceives() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            
            byte[] buf = new byte[50];
            byte[] inB = new byte[100];
            
            // Setup fragment length requiring multiple receives
            Encdec.enc_uint16le((short) 80, inB, 8);
            
            when(mockSmbPipeHandleInternal.isStale()).thenReturn(false);
            when(mockSmbPipeHandleInternal.sendrecv(buf, 0, 50, inB, 4280)).thenReturn(40);
            when(mockSmbPipeHandleInternal.recv(inB, 40, 40)).thenReturn(40);
            
            int result = handle.doSendReceiveFragment(buf, 0, 50, inB);
            assertEquals(80, result);
            verify(mockSmbPipeHandleInternal).recv(inB, 40, 40);
        }

        @Test
        @DisplayName("Should throw IOException when handle is stale")
        void testDoSendReceiveFragment_StaleHandle() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            when(mockSmbPipeHandleInternal.isStale()).thenReturn(true);
            
            assertThrows(IOException.class, 
                () -> handle.doSendReceiveFragment(new byte[10], 0, 10, new byte[10]));
        }

        @Test
        @DisplayName("Should throw IOException for fragment length exceeding max")
        void testDoSendReceiveFragment_FragmentTooLarge() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            
            byte[] buf = new byte[50];
            byte[] inB = new byte[100];
            
            // Setup fragment length exceeding max (4280)
            Encdec.enc_uint16le((short) 4281, inB, 8);
            
            when(mockSmbPipeHandleInternal.isStale()).thenReturn(false);
            when(mockSmbPipeHandleInternal.sendrecv(buf, 0, 50, inB, 4280)).thenReturn(40);
            
            assertThrows(IOException.class, 
                () -> handle.doSendReceiveFragment(buf, 0, 50, inB));
        }

        @Test
        @DisplayName("Should throw IOException on unexpected EOF")
        void testDoSendReceiveFragment_UnexpectedEOF() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            
            byte[] buf = new byte[50];
            byte[] inB = new byte[100];
            
            Encdec.enc_uint16le((short) 80, inB, 8);
            
            when(mockSmbPipeHandleInternal.isStale()).thenReturn(false);
            when(mockSmbPipeHandleInternal.sendrecv(buf, 0, 50, inB, 4280)).thenReturn(40);
            when(mockSmbPipeHandleInternal.recv(inB, 40, 40)).thenReturn(0); // EOF
            
            assertThrows(IOException.class, 
                () -> handle.doSendReceiveFragment(buf, 0, 50, inB));
        }
    }

    @Nested
    @DisplayName("Send Fragment Tests")
    class SendFragmentTests {

        @Test
        @DisplayName("Should send fragment successfully")
        void testDoSendFragment_Success() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            
            byte[] buf = new byte[100];
            when(mockSmbPipeHandleInternal.isStale()).thenReturn(false);
            
            handle.doSendFragment(buf, 10, 50);
            verify(mockSmbPipeHandleInternal).send(buf, 10, 50);
        }

        @Test
        @DisplayName("Should throw IOException when handle is stale")
        void testDoSendFragment_StaleHandle() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            when(mockSmbPipeHandleInternal.isStale()).thenReturn(true);
            
            assertThrows(IOException.class, 
                () -> handle.doSendFragment(new byte[10], 0, 10));
        }
    }

    @Nested
    @DisplayName("Receive Fragment Tests")
    class ReceiveFragmentTests {

        @Test
        @DisplayName("Should receive fragment successfully")
        void testDoReceiveFragment_Success() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            
            byte[] buf = new byte[4280];  // Use maxRecv size
            
            // Mock initial receive with valid PDU header
            when(mockSmbPipeHandleInternal.recv(buf, 0, 4280)).thenAnswer(invocation -> {
                byte[] buffer = invocation.getArgument(0);
                buffer[0] = 5; // Valid PDU version
                buffer[1] = 0; // Valid PDU type
                Encdec.enc_uint16le((short) 50, buffer, 8); // Fragment length
                return 30; // Initial bytes received
            });
            
            // Mock second receive to complete fragment
            when(mockSmbPipeHandleInternal.recv(buf, 30, 20)).thenReturn(20);
            
            int result = handle.doReceiveFragment(buf);
            assertEquals(50, result);
            verify(mockSmbPipeHandleInternal, times(2)).recv(any(byte[].class), anyInt(), anyInt());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException for small buffer")
        void testDoReceiveFragment_BufferTooSmall() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            
            byte[] buf = new byte[50]; // Less than maxRecv (4280)
            
            assertThrows(IllegalArgumentException.class, 
                () -> handle.doReceiveFragment(buf));
        }

        @Test
        @DisplayName("Should throw IOException for invalid PDU header")
        void testDoReceiveFragment_InvalidPDUHeader() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            
            byte[] buf = new byte[4280];
            
            when(mockSmbPipeHandleInternal.recv(buf, 0, 4280)).thenAnswer(invocation -> {
                byte[] buffer = invocation.getArgument(0);
                buffer[0] = 1; // Invalid PDU version
                buffer[1] = 0;
                return 20;
            });
            
            assertThrows(IOException.class, 
                () -> handle.doReceiveFragment(buf));
        }

        @Test
        @DisplayName("Should throw IOException for fragment length exceeding max")
        void testDoReceiveFragment_FragmentTooLarge() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            
            byte[] buf = new byte[4280];
            
            when(mockSmbPipeHandleInternal.recv(buf, 0, 4280)).thenAnswer(invocation -> {
                byte[] buffer = invocation.getArgument(0);
                buffer[0] = 5;
                buffer[1] = 0;
                Encdec.enc_uint16le((short) 4281, buffer, 8); // Exceeds maxRecv
                return 20;
            });
            
            assertThrows(IOException.class, 
                () -> handle.doReceiveFragment(buf));
        }

        @Test
        @DisplayName("Should throw IOException on unexpected EOF")
        void testDoReceiveFragment_UnexpectedEOF() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            
            byte[] buf = new byte[4280];
            
            when(mockSmbPipeHandleInternal.recv(buf, 0, 4280)).thenAnswer(invocation -> {
                byte[] buffer = invocation.getArgument(0);
                buffer[0] = 5;
                buffer[1] = 0;
                Encdec.enc_uint16le((short) 50, buffer, 8);
                return 30;
            });
            
            when(mockSmbPipeHandleInternal.recv(buf, 30, 20)).thenReturn(0); // EOF
            
            assertThrows(IOException.class, 
                () -> handle.doReceiveFragment(buf));
        }
    }

    @Nested
    @DisplayName("Close Tests")
    class CloseTests {

        @Test
        @DisplayName("Should close handle and pipe successfully")
        void testClose_Success() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            
            // Mock parent close() to do nothing
            doNothing().when((DcerpcHandle)handle).close();
            
            handle.close();
            
            verify(mockSmbPipeHandleInternal).close();
            verify(mockSmbNamedPipe).close();
        }

        @Test
        @DisplayName("Should close pipe even when handle close fails")
        void testClose_HandleCloseFails() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            
            // Mock parent close() method
            doNothing().when((DcerpcHandle)handle).close();
            
            doThrow(new IOException("Handle close failed"))
                .when(mockSmbPipeHandleInternal).close();
            
            // The finally block ensures pipe is closed even if handle close fails
            handle.close();
            
            verify(mockSmbPipeHandleInternal).close();
            verify(mockSmbNamedPipe).close(); // Should still be called due to finally block
        }
    }

    @Nested
    @DisplayName("Make Pipe URL Tests")
    class MakePipeUrlTests {

        @Test
        @DisplayName("Should generate correct pipe URL without options")
        void testMakePipeUrl_NoOptions() throws Exception {
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            
            Method makePipeUrlMethod = DcerpcPipeHandle.class.getDeclaredMethod("makePipeUrl");
            makePipeUrlMethod.setAccessible(true);
            String result = (String) makePipeUrlMethod.invoke(handle);
            
            assertEquals("smb://server/IPC$/test", result);
        }

        @Test
        @DisplayName("Should generate correct pipe URL with server option")
        void testMakePipeUrl_WithServerOption() throws Exception {
            when(mockDcerpcBinding.getOption("server")).thenReturn("customServer");
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            
            Method makePipeUrlMethod = DcerpcPipeHandle.class.getDeclaredMethod("makePipeUrl");
            makePipeUrlMethod.setAccessible(true);
            String result = (String) makePipeUrlMethod.invoke(handle);
            
            assertEquals("smb://server/IPC$/test?server=customServer", result);
        }

        @Test
        @DisplayName("Should generate correct pipe URL with address option")
        void testMakePipeUrl_WithAddressOption() throws Exception {
            lenient().when(mockDcerpcBinding.getOption("server")).thenReturn(null);
            when(mockDcerpcBinding.getOption("address")).thenReturn("192.168.1.1");
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            
            Method makePipeUrlMethod = DcerpcPipeHandle.class.getDeclaredMethod("makePipeUrl");
            makePipeUrlMethod.setAccessible(true);
            String result = (String) makePipeUrlMethod.invoke(handle);
            
            assertEquals("smb://server/IPC$/test?address=192.168.1.1", result);
        }

        @Test
        @DisplayName("Should generate correct pipe URL with both options")
        void testMakePipeUrl_WithBothOptions() throws Exception {
            when(mockDcerpcBinding.getOption("server")).thenReturn("customServer");
            when(mockDcerpcBinding.getOption("address")).thenReturn("192.168.1.1");
            DcerpcPipeHandle handle = createMockedDcerpcPipeHandle();
            
            Method makePipeUrlMethod = DcerpcPipeHandle.class.getDeclaredMethod("makePipeUrl");
            makePipeUrlMethod.setAccessible(true);
            String result = (String) makePipeUrlMethod.invoke(handle);
            
            assertEquals("smb://server/IPC$/test?server=customServer&address=192.168.1.1", result);
        }
    }

    @Nested
    @DisplayName("Pipe Flags Tests")
    class PipeFlagsTests {

        @Test
        @DisplayName("Should have correct pipe flags constant")
        void testPipeFlags() {
            int expectedFlags = (0x2019F << 16) | SmbPipeResource.PIPE_TYPE_RDWR | SmbPipeResource.PIPE_TYPE_DCE_TRANSACT;
            assertEquals(expectedFlags, DcerpcPipeHandle.pipeFlags);
        }
    }
}