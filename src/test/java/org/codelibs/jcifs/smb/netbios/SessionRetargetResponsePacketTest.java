package org.codelibs.jcifs.smb.netbios;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SessionRetargetResponsePacketTest {

    @Mock
    private InputStream mockInputStream;

    @Test
    void constructorShouldInitializeTypeAndLength() {
        // Test that the constructor correctly initializes the type and length fields.
        SessionRetargetResponsePacket packet = new SessionRetargetResponsePacket();
        assertEquals(SessionServicePacket.SESSION_RETARGET_RESPONSE, packet.type);
        assertEquals(6, packet.length);
    }

    @Test
    void writeTrailerWireFormatShouldReturnZero() {
        // Test that writeTrailerWireFormat always returns 0, as per its implementation.
        SessionRetargetResponsePacket packet = new SessionRetargetResponsePacket();
        assertEquals(0, packet.writeTrailerWireFormat(new byte[0], 0));
    }

    @Test
    void readTrailerWireFormatShouldReadSixBytesSuccessfully() throws IOException {
        // Test successful reading of 6 bytes from the input stream.
        // The content of these bytes is not critical for this test, only that 6 bytes are read.
        byte[] data = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }; // Sample 6 bytes
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        SessionRetargetResponsePacket packet = new SessionRetargetResponsePacket();

        // Create a buffer large enough to hold the read bytes
        byte[] buffer = new byte[6];
        int bytesRead = packet.readTrailerWireFormat(bais, buffer, 0);

        // Verify that 6 bytes were read, which is the expected length.
        assertEquals(6, bytesRead);
    }

    @Test
    void readTrailerWireFormatShouldThrowIOExceptionOnUnexpectedEOF() throws IOException {
        // Test that an IOException is thrown if the input stream does not provide enough bytes.
        // Simulate reading less than 6 bytes.
        when(mockInputStream.read(any(byte[].class), anyInt(), anyInt())).thenReturn(5); // Simulate reading only 5 bytes

        SessionRetargetResponsePacket packet = new SessionRetargetResponsePacket();
        byte[] buffer = new byte[6];

        // Assert that an IOException is thrown with the expected message.
        IOException thrown = assertThrows(IOException.class, () -> {
            packet.readTrailerWireFormat(mockInputStream, buffer, 0);
        });
        assertTrue(thrown.getMessage().contains("unexpected EOF reading netbios retarget session response"));
    }
}
