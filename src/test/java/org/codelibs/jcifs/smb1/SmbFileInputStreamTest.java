package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.codelibs.jcifs.smb1.util.transport.TransportException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Reading a file the way a crawler does, through {@link SmbFileInputStream}.
 *
 * <p>
 * The file is a spy whose {@code open}, {@code close} and {@code send} are stubbed, and {@code send} answers each
 * READ_ANDX from an in-memory array. Everything between the caller and that array is the real stream: how a read is
 * split to fit the negotiated buffer, how the file pointer moves, where the end of the file is detected and how a
 * failure is reported.
 * </p>
 */
class SmbFileInputStreamTest {

    /** The largest read the stream may ask for, kept small so that one call spans several requests. */
    private static final int READ_SIZE = 16;

    private final List<Long> offsets = new ArrayList<>();
    private final List<Integer> counts = new ArrayList<>();

    private static byte[] contents(final int length) {
        final byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) (i * 7 + 3);
        }
        return bytes;
    }

    private static long offsetOf(final SmbComReadAndX request) throws Exception {
        final Field field = SmbComReadAndX.class.getDeclaredField("offset");
        field.setAccessible(true);
        return field.getLong(request);
    }

    /** A file that serves {@code contents}, at most {@code perRequest} bytes for each READ_ANDX. */
    private SmbFile serving(final byte[] contents, final int perRequest) throws Exception {
        final NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication("DOMAIN", "crawler", "secret");
        final UniAddress address = new UniAddress(InetAddress.getLoopbackAddress());
        final SmbTransport transport = new SmbTransport(address, 445, null, 0);
        transport.server.maxBufferSize = READ_SIZE + 70;
        final SmbSession session = new SmbSession(address, 445, null, 0, auth);
        session.transport = transport;

        final SmbFile file = new SmbFile("smb1://server/share/data.bin", auth);
        file.tree = new SmbTree(session, "share", null);

        final SmbFile spied = spy(file);
        doNothing().when(spied).open(anyInt(), anyInt(), anyInt(), anyInt());
        doNothing().when(spied).close();
        doAnswer(invocation -> {
            final SmbComReadAndX request = invocation.getArgument(0);
            final SmbComReadAndXResponse response = invocation.getArgument(1);
            final long offset = offsetOf(request);
            this.offsets.add(offset);
            this.counts.add(request.maxCount);
            final int served = (int) Math.max(0L, Math.min(Math.min(request.maxCount, perRequest), contents.length - offset));
            if (served > 0) {
                System.arraycopy(contents, (int) offset, response.b, response.off, served);
            }
            response.dataLength = served;
            return null;
        }).when(spied).send(any(ServerMessageBlock.class), any(ServerMessageBlock.class));
        return spied;
    }

    @Test
    @DisplayName("one read spanning several requests walks the file pointer through the file and then reports the end")
    void oneReadSpansSeveralRequests() throws Exception {
        final byte[] contents = contents(50);

        try (SmbFileInputStream in = new SmbFileInputStream(serving(contents, Integer.MAX_VALUE))) {
            final byte[] buffer = new byte[64];

            assertEquals(50, in.read(buffer, 0, 50));
            assertArrayEquals(contents, Arrays.copyOf(buffer, 50));
            assertEquals(List.of(0L, 16L, 32L, 48L), this.offsets);
            assertEquals(List.of(16, 16, 16, 2), this.counts);

            assertEquals(-1, in.read(buffer), "a read at the end of the file should report the end");
            assertEquals(50L, this.offsets.get(this.offsets.size() - 1));
        }
    }

    @Test
    @DisplayName("a buffered copy gets every byte even when the server answers each request short")
    void bufferedCopyGetsEveryByte() throws Exception {
        final byte[] contents = contents(1000);
        final ByteArrayOutputStream out = new ByteArrayOutputStream();

        try (InputStream in = new BufferedInputStream(new SmbFileInputStream(serving(contents, 5)))) {
            final byte[] buffer = new byte[1024];
            int length;
            while (-1 < (length = in.read(buffer))) {
                out.write(buffer, 0, length);
            }
        }

        assertArrayEquals(contents, out.toByteArray());
        assertTrue(this.counts.stream().allMatch(count -> count <= READ_SIZE),
                "a request asked for more than the negotiated buffer: " + this.counts);
    }

    @Test
    @DisplayName("an empty file reports the end on the first read")
    void emptyFileEndsAtOnce() throws Exception {
        try (SmbFileInputStream in = new SmbFileInputStream(serving(new byte[0], Integer.MAX_VALUE))) {
            assertEquals(-1, in.read());
        }
    }

    @Test
    @DisplayName("closing the stream closes the file, and a read afterwards is refused")
    void readAfterCloseIsRefused() throws Exception {
        final SmbFile file = serving(contents(10), Integer.MAX_VALUE);
        final SmbFileInputStream in = new SmbFileInputStream(file);

        in.close();

        verify(file).close();
        final IOException e = assertThrows(IOException.class, () -> in.read(new byte[4]));
        assertEquals("Bad file descriptor", e.getMessage());
    }

    @Test
    @DisplayName("an interrupt while waiting for the server surfaces as InterruptedIOException")
    void interruptSurfacesAsInterruptedIoException() throws Exception {
        final SmbFile file = serving(contents(10), Integer.MAX_VALUE);
        final InterruptedException interrupt = new InterruptedException("interrupted");
        doThrow(new SmbException("read failed", new TransportException("wait interrupted", interrupt))).when(file)
                .send(any(ServerMessageBlock.class), any(ServerMessageBlock.class));

        try (SmbFileInputStream in = new SmbFileInputStream(file)) {
            final InterruptedIOException e = assertThrows(InterruptedIOException.class, () -> in.read(new byte[4]));
            assertSame(interrupt, e.getCause());
        }
    }

    @Test
    @DisplayName("a transport failure surfaces as the transport exception rather than a wrapped SMB error")
    void transportFailureSurfacesUnwrapped() throws Exception {
        final SmbFile file = serving(contents(10), Integer.MAX_VALUE);
        final TransportException failure = new TransportException("connection reset");
        doThrow(new SmbException("read failed", failure)).when(file).send(any(ServerMessageBlock.class), any(ServerMessageBlock.class));

        try (SmbFileInputStream in = new SmbFileInputStream(file)) {
            final IOException e = assertThrows(IOException.class, () -> in.read(new byte[4]));
            assertInstanceOf(TransportException.class, e);
            assertSame(failure, e);
        }
    }
}
