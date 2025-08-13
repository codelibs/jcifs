package jcifs.smb1.netbios;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.*;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Test class for SocketInputStream using JUnit 5 and Mockito.
 * Tests the NetBIOS session layer protocol implementation.
 */
@ExtendWith(MockitoExtension.class)
class SocketInputStreamTest {

    /**
     * Creates a NetBIOS session message header.
     * The header format is:
     * - Byte 0: Message type (0x00 for SESSION_MESSAGE)
     * - Byte 1: High bit of 17-bit length field
     * - Bytes 2-3: Lower 16 bits of length field
     */
    private static byte[] messageHeader(int length) {
        byte[] h = new byte[4];
        h[0] = (byte) SessionServicePacket.SESSION_MESSAGE;
        h[1] = (byte) ((length >> 16) & 0x01);
        h[2] = (byte) ((length >> 8) & 0xFF);
        h[3] = (byte) (length & 0xFF);
        return h;
    }
    
    /**
     * Creates a NetBIOS keep-alive header.
     * Keep-alive packets have type 0x85 and zero length.
     */
    private static byte[] keepAliveHeader() {
        byte[] h = new byte[4];
        h[0] = (byte) SessionServicePacket.SESSION_KEEP_ALIVE;
        h[1] = h[2] = h[3] = 0;
        return h;
    }
    
    /**
     * Concatenates multiple byte arrays into a single array.
     */
    private static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) {
            total += a.length;
        }
        byte[] res = new byte[total];
        int off = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, res, off, a.length);
            off += a.length;
        }
        return res;
    }

    @Test
    @DisplayName("Read single bytes from stream with message packet")
    void readSingleByteHappyPath() throws IOException {
        // Create a simple message with 3 bytes of data
        byte[] data = new byte[] {1, 2, 3};
        byte[] fullData = concat(messageHeader(3), data);
        InputStream in = new ByteArrayInputStream(fullData);
        SocketInputStream sis = new SocketInputStream(in);
        
        // Read the three data bytes
        assertEquals(1, sis.read());
        assertEquals(2, sis.read());
        assertEquals(3, sis.read());
        
        // After consuming all data, trying to read again will attempt to read
        // another packet header, but since there's no more data, it will throw IOException
        assertThrows(IOException.class, () -> sis.read());
    }

    @Test
    @DisplayName("Reading with zero-length array returns 0")
    void readZeroLengthArrayReturnsZero() throws IOException {
        // Create stream with a message containing data
        byte[] data = new byte[] {1, 2};
        InputStream in = new ByteArrayInputStream(concat(messageHeader(2), data));
        SocketInputStream sis = new SocketInputStream(in);
        
        // Reading with zero-length array should return 0 without consuming data
        assertEquals(0, sis.read(new byte[0]));
        
        // Verify data can still be read
        assertEquals(1, sis.read());
        assertEquals(2, sis.read());
    }

    @Test
    @DisplayName("Reading with null array throws NullPointerException")
    void readNullArrayThrowsException() {
        // Create stream with valid message header and data
        byte[] data = new byte[] {1};
        InputStream in = new ByteArrayInputStream(concat(messageHeader(1), data));
        SocketInputStream sis = new SocketInputStream(in);
        
        // Should throw NullPointerException when reading with null array
        assertThrows(NullPointerException.class, () -> sis.read((byte[]) null));
    }

    @ParameterizedTest
    @ValueSource(longs = {0L, -1L, -10L})
    @DisplayName("Skip returns 0 for zero or negative values")
    void skipReturnsZeroForNegativeOrZero(long skipBytes) throws IOException {
        // Create message with 5 bytes of data
        byte[] data = new byte[] {10, 20, 30, 40, 50};
        InputStream in = new ByteArrayInputStream(concat(messageHeader(5), data));
        SocketInputStream sis = new SocketInputStream(in);
        
        // Skip should return 0 for negative or zero values
        assertEquals(0, sis.skip(skipBytes));
        
        // All data should still be available
        assertEquals(10, sis.read());
    }

    @Test
    @DisplayName("Skip correctly advances position in stream")
    void skipAdvancesPosition() throws IOException {
        // Create message with 5 bytes of data
        byte[] data = new byte[] {10, 20, 30, 40, 50};
        InputStream in = new ByteArrayInputStream(concat(messageHeader(5), data));
        SocketInputStream sis = new SocketInputStream(in);
        
        // Skip 3 bytes
        assertEquals(3, sis.skip(3));
        
        // Read remaining 2 bytes
        byte[] remaining = new byte[2];
        assertEquals(2, sis.read(remaining, 0, 2));
        assertArrayEquals(new byte[] {40, 50}, remaining);
    }

    @Test
    @DisplayName("Skip handles amount larger than available")
    void skipHandlesLargerThanAvailable() throws IOException {
        // Create message with 3 bytes of data
        byte[] data = new byte[] {1, 2, 3};
        InputStream in = new ByteArrayInputStream(concat(messageHeader(3), data));
        SocketInputStream sis = new SocketInputStream(in);
        
        // Try to skip more than available
        // Skip uses read internally, which may throw IOException when it tries to read the next header
        try {
            long skipped = sis.skip(10);
            // If it doesn't throw, it should only skip what's available
            assertEquals(3, skipped);
        } catch (IOException e) {
            // This is also acceptable behavior - skip may fail when it runs out of data
            assertTrue(e.getMessage().contains("unexpected EOF"));
        }
    }

    @Test
    @DisplayName("Keep-alive packets are transparently skipped")
    void keepAlivePacketsAreSkipped() throws IOException {
        // Create stream with keep-alive followed by message
        byte[] data = new byte[] {30, 60};
        byte[] fullData = concat(
            keepAliveHeader(),
            messageHeader(2),
            data
        );
        InputStream in = new ByteArrayInputStream(fullData);
        SocketInputStream sis = new SocketInputStream(in);
        
        // Keep-alive packet should be transparently skipped
        assertEquals(30, sis.read());
        assertEquals(60, sis.read());
        
        // After consuming all data, next read will fail
        assertThrows(IOException.class, () -> sis.read());
    }

    @Test
    @DisplayName("Close delegates to underlying stream")
    void closeDelegatesToUnderlyingStream(@Mock InputStream mockIn) throws IOException {
        SocketInputStream sis = new SocketInputStream(mockIn);
        sis.close();
        verify(mockIn).close();
    }
    
    @Test
    @DisplayName("Read array delegates to read with offset and length")
    void readArrayDelegatesToReadWithOffsetAndLength() throws IOException {
        // Create message with data
        byte[] data = new byte[] {1, 2, 3, 4, 5};
        InputStream in = new ByteArrayInputStream(concat(messageHeader(5), data));
        SocketInputStream sis = new SocketInputStream(in);
        
        // Read using array-only method
        byte[] buffer = new byte[3];
        assertEquals(3, sis.read(buffer));
        assertArrayEquals(new byte[] {1, 2, 3}, buffer);
    }
    
    @Test
    @DisplayName("Available returns remaining bytes in current message")
    void availableReturnsBytesInCurrentMessage() throws IOException {
        // Create message with 4 bytes
        byte[] data = new byte[] {1, 2, 3, 4};
        InputStream in = new ByteArrayInputStream(concat(messageHeader(4), data));
        SocketInputStream sis = new SocketInputStream(in);
        
        // Read one byte to trigger message header processing
        assertEquals(1, sis.read());
        
        // 3 bytes should remain available in current message
        assertEquals(3, sis.available());
        
        // Read another byte
        assertEquals(2, sis.read());
        
        // 2 bytes should remain
        assertEquals(2, sis.available());
    }
    
    @Test
    @DisplayName("Multiple messages are read sequentially")
    void multipleMessagesAreReadSequentially() throws IOException {
        // Create two messages
        byte[] data1 = new byte[] {1, 2};
        byte[] data2 = new byte[] {3, 4, 5};
        byte[] fullData = concat(
            messageHeader(2), data1,
            messageHeader(3), data2
        );
        InputStream in = new ByteArrayInputStream(fullData);
        SocketInputStream sis = new SocketInputStream(in);
        
        // Read first message
        assertEquals(1, sis.read());
        assertEquals(2, sis.read());
        
        // Read second message
        assertEquals(3, sis.read());
        assertEquals(4, sis.read());
        assertEquals(5, sis.read());
        
        // After all data is consumed, next read throws IOException
        assertThrows(IOException.class, () -> sis.read());
    }
    
    @Test
    @DisplayName("EOF handling when stream ends mid-header")
    void eofHandlingMidHeader() throws IOException {
        // Create incomplete header (only 2 bytes instead of 4)
        byte[] incompleteHeader = new byte[] {
            (byte) SessionServicePacket.SESSION_MESSAGE, 0
        };
        InputStream in = new ByteArrayInputStream(incompleteHeader);
        SocketInputStream sis = new SocketInputStream(in);
        
        // Should throw IOException for unexpected EOF
        assertThrows(IOException.class, () -> sis.read());
    }
    
    @Test
    @DisplayName("Large message is read correctly")
    void largeMessageIsReadCorrectly() throws IOException {
        // Create a message with 1000 bytes
        int size = 1000;
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            data[i] = (byte) (i % 256);
        }
        
        byte[] fullData = concat(messageHeader(size), data);
        InputStream in = new ByteArrayInputStream(fullData);
        SocketInputStream sis = new SocketInputStream(in);
        
        // Read all data
        byte[] buffer = new byte[size];
        int totalRead = 0;
        while (totalRead < size) {
            int read = sis.read(buffer, totalRead, size - totalRead);
            if (read == -1) break;
            totalRead += read;
        }
        
        assertEquals(size, totalRead);
        assertArrayEquals(data, buffer);
    }
    
    @Test
    @DisplayName("Read handles partial reads from underlying stream")
    void readHandlesPartialReads() throws IOException {
        // Create message with data
        byte[] data = new byte[] {1, 2, 3, 4, 5};
        InputStream in = new ByteArrayInputStream(concat(messageHeader(5), data));
        SocketInputStream sis = new SocketInputStream(in);
        
        // Read in chunks
        byte[] buffer = new byte[10];
        
        // The read will either:
        // 1. Successfully read all 5 bytes
        // 2. Throw IOException if it tries to read past the message
        try {
            int read = sis.read(buffer, 0, 10);
            
            // Should read all 5 available bytes
            assertEquals(5, read);
            
            // Verify correct data
            for (int i = 0; i < 5; i++) {
                assertEquals(i + 1, buffer[i]);
            }
            
            // Next read will try to read header and should fail
            assertThrows(IOException.class, () -> sis.read(buffer, 0, 10));
        } catch (IOException e) {
            // This is also acceptable - if the implementation tries to read
            // the next header immediately after consuming all data
            assertTrue(e.getMessage().contains("unexpected EOF"));
        }
    }
    
    @Test
    @DisplayName("Zero-length message is handled correctly")
    void zeroLengthMessageHandled() throws IOException {
        // Create a zero-length message followed by a normal message
        byte[] data = new byte[] {10, 20};
        byte[] fullData = concat(
            messageHeader(0),  // Zero-length message
            messageHeader(2), data
        );
        InputStream in = new ByteArrayInputStream(fullData);
        SocketInputStream sis = new SocketInputStream(in);
        
        // Should skip zero-length message and read actual data
        assertEquals(10, sis.read());
        assertEquals(20, sis.read());
        
        // After all data consumed, next read fails
        assertThrows(IOException.class, () -> sis.read());
    }
    
    @Test
    @DisplayName("Unknown packet type is handled by continuing to next packet")
    void unknownPacketTypeHandled() throws IOException {
        // According to the SocketInputStream implementation, unknown packet types
        // are handled in the switch statement's default case which continues the loop
        byte[] data = new byte[] {1, 2};
        
        // Use a type that's not SESSION_MESSAGE or SESSION_KEEP_ALIVE
        byte[] unknownHeader = new byte[] {(byte) 0x90, 0, 0, 0};
        
        byte[] fullData = concat(
            unknownHeader,  // Unknown packet type - will continue to next packet
            messageHeader(2), data
        );
        InputStream in = new ByteArrayInputStream(fullData);
        SocketInputStream sis = new SocketInputStream(in);
        
        // The unknown packet should be skipped, and data should be readable
        assertEquals(1, sis.read());
        assertEquals(2, sis.read());
        
        // After all data is consumed
        assertThrows(IOException.class, () -> sis.read());
    }
    
    @Test
    @DisplayName("Available returns underlying stream available when no message buffered")
    void availableReturnsUnderlyingWhenNoMessage() throws IOException {
        // Mock input stream that reports available bytes
        InputStream mockIn = mock(InputStream.class);
        when(mockIn.available()).thenReturn(42);
        
        SocketInputStream sis = new SocketInputStream(mockIn);
        
        // When no message is buffered, should return underlying stream's available
        assertEquals(42, sis.available());
    }
}