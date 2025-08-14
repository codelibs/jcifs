package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.reflect.Field;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.internal.CommonServerMessageBlockResponse;
import jcifs.internal.Request;
import jcifs.internal.smb2.io.Smb2ReadRequest;
import jcifs.internal.smb2.io.Smb2ReadResponse;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SmbFileInputStreamTest {

    @Mock
    SmbFile mockFile;

    @Mock
    SmbTreeHandleImpl mockTree;

    @Mock
    SmbFileHandleImpl mockHandle;

    @Mock
    Configuration mockConfig;

    private SmbFileInputStream newStream() throws SmbException {
        // Constructor that avoids external I/O; stays in-memory
        when(mockTree.isSMB2()).thenReturn(true); // default SMB2 for simple happy-path
        return new SmbFileInputStream(mockFile, mockTree, mockHandle);
    }

    @BeforeEach
    void setUp() throws Exception {
        // Common, safe defaults for collaborators
        when(mockHandle.isValid()).thenReturn(true);
        when(mockHandle.acquire()).thenReturn(mockHandle);
        when(mockHandle.getTree()).thenReturn(mockTree);
        when(mockHandle.getFileId()).thenReturn(new byte[16]);

        when(mockTree.getReceiveBufferSize()).thenReturn(0x10000);
        when(mockTree.getMaximumBufferSize()).thenReturn(0x10000);
        when(mockTree.getConfig()).thenReturn(mockConfig);
        when(mockTree.isConnected()).thenReturn(true);
        when(mockTree.getTreeId()).thenReturn(1L);

        when(mockFile.getType()).thenReturn(SmbConstants.TYPE_FILESYSTEM);
    }

    @Nested
    @DisplayName("Happy path")
    class HappyPath {

        @Test
        @DisplayName("readDirect over SMB2 returns bytes read and uses current offset")
        void readDirectSmb2Happy() throws Exception {
            SmbFileInputStream in = newStream();

            // Arrange SMB2 response to return 3 bytes
            Smb2ReadResponse smb2Resp = mock(Smb2ReadResponse.class);
            when(smb2Resp.getDataLength()).thenReturn(3);
            when(mockTree.send(any(Request.class), any(RequestParam.class))).thenAnswer(inv -> (CommonServerMessageBlockResponse) smb2Resp);

            byte[] buf = new byte[16];

            // Skip advances internal file pointer; next read should use this offset
            in.skip(2);

            // Act
            int n = in.readDirect(buf, 0, 5);

            // Assert
            assertEquals(3, n, "Should report bytes read from SMB2 response");

            // Verify the request offset equals the skip value (2)
            ArgumentCaptor<Smb2ReadRequest> cap = ArgumentCaptor.forClass(Smb2ReadRequest.class);
            verify(mockTree).send(cap.capture(), any(RequestParam.class));
            Smb2ReadRequest req = cap.getValue();

            // Reflectively inspect the private 'offset' field to assert it used the advanced fp
            Field offField = Smb2ReadRequest.class.getDeclaredField("offset");
            offField.setAccessible(true);
            long offVal = offField.getLong(req);
            assertEquals(2L, offVal, "Request offset should match skipped bytes");
        }

        @Test
        @DisplayName("read(byte[]) delegates to read(byte[],off,len)")
        void readArrayDelegates() throws Exception {
            SmbFileInputStream in = newStream();

            Smb2ReadResponse smb2Resp = mock(Smb2ReadResponse.class);
            when(smb2Resp.getDataLength()).thenReturn(3);
            when(mockTree.send(any(Request.class), any(RequestParam.class))).thenAnswer(inv -> (CommonServerMessageBlockResponse) smb2Resp);

            byte[] buf = new byte[8];
            int n = in.read(buf);
            assertEquals(3, n);
        }

        @Test
        @DisplayName("read() returns -1 when underlying readDirect hits EOF")
        void readSingleByteEOF() throws Exception {
            // Arrange SMB2 EOF via NT status code mapping in SmbFileInputStream
            when(mockTree.send(any(Request.class), any(RequestParam.class))).thenThrow(new SmbException(0xC0000011, false)); // STATUS_END_OF_FILE

            SmbFileInputStream in = newStream();
            int v = in.read();
            assertEquals(-1, v);
        }
    }

    @Nested
    @DisplayName("Edge and invalid inputs")
    class EdgeCases {

        @Test
        @DisplayName("read(null) throws NullPointerException")
        void readNullArrayThrows() throws Exception {
            SmbFileInputStream in = newStream();
            assertThrows(NullPointerException.class, () -> in.read(null));
        }

        @Test
        @DisplayName("readDirect with len <= 0 returns 0")
        void readDirectZeroLen() throws Exception {
            SmbFileInputStream in = newStream();
            byte[] buf = new byte[4];
            assertEquals(0, in.readDirect(buf, 0, 0));
            assertEquals(0, in.read(new byte[0]));
        }

        @Test
        @DisplayName("read after close throws 'Bad file descriptor'")
        void readAfterCloseThrows() throws Exception {
            SmbFileInputStream in = newStream();
            // closing should null tmp; subsequent readDirect should fail
            in.close();
            IOException ex = assertThrows(IOException.class, () -> in.readDirect(new byte[8], 0, 4));
            assertTrue(ex.getMessage().contains("Bad file descriptor"));
        }

        @Test
        @DisplayName("available always returns 0")
        void availableAlwaysZero() throws Exception {
            SmbFileInputStream in = newStream();
            assertEquals(0, in.available());
        }

        @Test
        @DisplayName("skip: positive advances; non-positive returns 0")
        void skipBehavior() throws Exception {
            SmbFileInputStream in = newStream();
            assertEquals(0, in.skip(0));
            assertEquals(0, in.skip(-1));
            assertEquals(5, in.skip(5));
        }
    }

    @Nested
    @DisplayName("SMB1 interactions")
    class Smb1Behavior {

        @Test
        @DisplayName("Named pipe: broken pipe maps to -1")
        void namedPipeBrokenPipeReturnsMinusOne() throws Exception {
            when(mockTree.isSMB2()).thenReturn(false);
            when(mockFile.getType()).thenReturn(SmbConstants.TYPE_NAMED_PIPE);

            // th.send(request, response, ...) throws SmbException with NT_STATUS_PIPE_BROKEN
            doThrow(new SmbException(NtStatus.NT_STATUS_PIPE_BROKEN, false)).when(mockTree).send(
                    any(jcifs.internal.CommonServerMessageBlockRequest.class), any(jcifs.internal.CommonServerMessageBlockResponse.class),
                    any(RequestParam.class));

            SmbFileInputStream in = new SmbFileInputStream(mockFile, mockTree, mockHandle);
            int res = in.readDirect(new byte[1024], 0, 256);
            assertEquals(-1, res);
        }

        @Test
        @DisplayName("LargeReadX splits count across maxCount/openTimeout")
        void largeReadXSetsRequestFields() throws Exception {
            when(mockTree.isSMB2()).thenReturn(false);
            when(mockTree.hasCapability(SmbConstants.CAP_LARGE_READX)).thenReturn(true);
            when(mockTree.areSignaturesActive()).thenReturn(false);
            when(mockConfig.getReceiveBufferSize()).thenReturn(0x200000); // large to allow big block size
            when(mockTree.getReceiveBufferSize()).thenReturn(0x200000);
            when(mockTree.getMaximumBufferSize()).thenReturn(0x200000);

            // Make TYPE_FILESYSTEM path, not named pipe
            when(mockFile.getType()).thenReturn(SmbConstants.TYPE_FILESYSTEM);

            // Capture the ReadAndX request; throw to short-circuit network
            doAnswer(inv -> {
                throw new SmbException("short-circuit");
            }).when(mockTree).send(any(jcifs.internal.CommonServerMessageBlockRequest.class),
                    any(jcifs.internal.CommonServerMessageBlockResponse.class), any(RequestParam.class));

            SmbFileInputStream in = new SmbFileInputStream(mockFile, mockTree, mockHandle);

            ArgumentCaptor<jcifs.internal.smb1.com.SmbComReadAndX> cap =
                    ArgumentCaptor.forClass(jcifs.internal.smb1.com.SmbComReadAndX.class);

            // Act: choose len so upper/lower 16-bit parts are exercised
            byte[] buf = new byte[0x30000];
            try {
                in.readDirect(buf, 0, 0x12345);
                fail("Expected IOException due to short-circuit");
            } catch (IOException expected) {
                // expected
            }

            // Assert captured request parameters
            verify(mockTree).send(cap.capture(), any(jcifs.internal.CommonServerMessageBlockResponse.class), any(RequestParam.class));
            jcifs.internal.smb1.com.SmbComReadAndX req = cap.getValue();
            assertEquals(0x12345 & 0xFFFF, req.getMaxCount(), "maxCount should contain lower 16 bits");
            assertEquals(0x12345, req.getMinCount(), "minCount should remain original full value");
        }

        @Test
        @DisplayName("Named pipe request uses fixed 1024 hints")
        void namedPipeRequestHints() throws Exception {
            when(mockTree.isSMB2()).thenReturn(false);
            when(mockFile.getType()).thenReturn(SmbConstants.TYPE_NAMED_PIPE);

            // Cause send to throw to stop execution so we can verify arguments
            doAnswer(inv -> {
                throw new SmbException("stop");
            }).when(mockTree).send(any(jcifs.internal.CommonServerMessageBlockRequest.class),
                    any(jcifs.internal.CommonServerMessageBlockResponse.class), any(RequestParam.class));

            SmbFileInputStream in = new SmbFileInputStream(mockFile, mockTree, mockHandle);
            ArgumentCaptor<jcifs.internal.smb1.com.SmbComReadAndX> cap =
                    ArgumentCaptor.forClass(jcifs.internal.smb1.com.SmbComReadAndX.class);

            try {
                in.readDirect(new byte[4096], 0, 2048);
                fail("Expected IOException");
            } catch (IOException expected) {
                // expected
            }

            verify(mockTree).send(cap.capture(), any(jcifs.internal.CommonServerMessageBlockResponse.class), any(RequestParam.class));
            jcifs.internal.smb1.com.SmbComReadAndX req = cap.getValue();
            assertEquals(1024, req.getMinCount(), "Named pipe minCount should be 1024");
            assertEquals(1024, req.getMaxCount(), "Named pipe maxCount should be 1024");
            assertEquals(1024, req.getRemaining(), "Named pipe remaining should be 1024");
        }
    }

    @Nested
    @DisplayName("Lifecycle and exception mapping")
    class LifecycleAndExceptions {

        @Test
        @DisplayName("open() acquires handle and closes it")
        void openDelegatesEnsureOpenAndCloses() throws Exception {
            SmbFileInputStream in = newStream();
            in.open();
            // ensureOpen returns acquired handle; try-with-resources must close it
            verify(mockHandle, times(1)).close();
            verify(mockHandle, atLeastOnce()).acquire();
        }

        @Test
        @DisplayName("close() closes handle; does not close file when not unshared")
        void closeClosesHandle() throws Exception {
            SmbFileInputStream in = newStream();
            in.close();
            verify(mockHandle, times(1)).close();
            verify(mockFile, never()).close();
        }

        @Test
        @DisplayName("seToIoe maps Interrupted cause to InterruptedIOException")
        void seToIoeInterruptedMapping() {
            SmbException se = new SmbException("x", new jcifs.util.transport.TransportException(new InterruptedException("boom")));
            IOException ioe = SmbFileInputStream.seToIoe(se);
            assertTrue(ioe instanceof InterruptedIOException);
            assertTrue(ioe.getMessage().contains("boom"));
        }
    }
}
