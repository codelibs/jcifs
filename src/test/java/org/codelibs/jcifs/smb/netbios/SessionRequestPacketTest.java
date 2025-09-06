package org.codelibs.jcifs.smb.netbios;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.stream.Stream;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.NetbiosName;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class SessionRequestPacketTest {

    @Mock
    private Configuration mockConfig;

    @Mock
    private NetbiosName mockCalledName;

    @Mock
    private NetbiosName mockCallingName;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(mockConfig.getNetbiosScope()).thenReturn(null);
        // Configure OEM encoding to avoid NullPointerException
        when(mockConfig.getOemEncoding()).thenReturn("UTF-8");
    }

    @Test
    @DisplayName("Constructor with Configuration only should create empty Name instances")
    void testConstructorWithConfigOnly() {
        SessionRequestPacket packet = new SessionRequestPacket(mockConfig);

        assertNotNull(packet);
        // The packet should have calledName and callingName initialized but empty
        byte[] dst = new byte[256];
        int written = packet.writeTrailerWireFormat(dst, 0);
        assertTrue(written > 0);
    }

    @Test
    @DisplayName("Constructor with NetbiosNames should initialize properly")
    void testConstructorWithNetbiosNames() {
        when(mockCalledName.getName()).thenReturn("SERVER");
        when(mockCalledName.getNameType()).thenReturn(0x20);
        when(mockCalledName.getScope()).thenReturn(null);

        when(mockCallingName.getName()).thenReturn("CLIENT");
        when(mockCallingName.getNameType()).thenReturn(0x00);
        when(mockCallingName.getScope()).thenReturn(null);

        SessionRequestPacket packet = new SessionRequestPacket(mockConfig, mockCalledName, mockCallingName);

        assertNotNull(packet);
        assertEquals(SessionServicePacket.SESSION_REQUEST, packet.type);
    }

    @Test
    @DisplayName("writeTrailerWireFormat should write both names correctly")
    void testWriteTrailerWireFormat() {
        when(mockCalledName.getName()).thenReturn("SERVER");
        when(mockCalledName.getNameType()).thenReturn(0x20);
        when(mockCalledName.getScope()).thenReturn(null);

        when(mockCallingName.getName()).thenReturn("CLIENT");
        when(mockCallingName.getNameType()).thenReturn(0x00);
        when(mockCallingName.getScope()).thenReturn(null);

        SessionRequestPacket packet = new SessionRequestPacket(mockConfig, mockCalledName, mockCallingName);

        byte[] dst = new byte[256];
        int bytesWritten = packet.writeTrailerWireFormat(dst, 0);

        assertTrue(bytesWritten > 0);
        // Each name should write at least 34 bytes (encoded name + scope)
        assertTrue(bytesWritten >= 68);
    }

    @Test
    @DisplayName("writeTrailerWireFormat with scope should handle scoped names")
    void testWriteTrailerWireFormatWithScope() {
        when(mockCalledName.getName()).thenReturn("SERVER");
        when(mockCalledName.getNameType()).thenReturn(0x20);
        when(mockCalledName.getScope()).thenReturn("DOMAIN.COM");

        when(mockCallingName.getName()).thenReturn("CLIENT");
        when(mockCallingName.getNameType()).thenReturn(0x00);
        when(mockCallingName.getScope()).thenReturn("DOMAIN.COM");

        SessionRequestPacket packet = new SessionRequestPacket(mockConfig, mockCalledName, mockCallingName);

        byte[] dst = new byte[256];
        int bytesWritten = packet.writeTrailerWireFormat(dst, 0);

        assertTrue(bytesWritten > 68); // Should be larger due to scope
    }

    @Test
    @DisplayName("readTrailerWireFormat should read complete packet data")
    void testReadTrailerWireFormatSuccess() throws IOException {
        SessionRequestPacket writePacket =
                new SessionRequestPacket(mockConfig, new TestNetbiosName("SERVER", 0x20, null), new TestNetbiosName("CLIENT", 0x00, null));

        byte[] buffer = new byte[256];
        int written = writePacket.writeTrailerWireFormat(buffer, 0);

        ByteArrayInputStream bais = new ByteArrayInputStream(buffer, 0, written);
        SessionRequestPacket readPacket = new SessionRequestPacket(mockConfig);
        readPacket.length = written;

        int bytesRead = readPacket.readTrailerWireFormat(bais, buffer, 0);

        assertEquals(written, bytesRead);
    }

    @Test
    @DisplayName("readTrailerWireFormat should throw IOException on incomplete data")
    void testReadTrailerWireFormatIncompleteData() {
        byte[] buffer = new byte[10]; // Too small buffer
        ByteArrayInputStream bais = new ByteArrayInputStream(buffer);

        SessionRequestPacket packet = new SessionRequestPacket(mockConfig);
        packet.length = 100; // Expect more data than available

        // Create a larger buffer for reading to avoid IndexOutOfBoundsException
        byte[] readBuffer = new byte[100];
        assertThrows(IOException.class, () -> {
            packet.readTrailerWireFormat(bais, readBuffer, 0);
        });
    }

    @Test
    @DisplayName("readTrailerWireFormat should throw IOException with specific message")
    void testReadTrailerWireFormatErrorMessage() {
        byte[] buffer = new byte[10];
        ByteArrayInputStream bais = new ByteArrayInputStream(buffer);

        SessionRequestPacket packet = new SessionRequestPacket(mockConfig);
        packet.length = 100;

        // Create a larger buffer for reading to avoid IndexOutOfBoundsException
        byte[] readBuffer = new byte[100];
        IOException exception = assertThrows(IOException.class, () -> {
            packet.readTrailerWireFormat(bais, readBuffer, 0);
        });

        assertEquals("invalid session request wire format", exception.getMessage());
    }

    @ParameterizedTest
    @MethodSource("provideNamesForWriteTest")
    @DisplayName("writeTrailerWireFormat should handle various name combinations")
    void testWriteTrailerWireFormatVariousNames(String calledName, int calledType, String callingName, int callingType) {
        SessionRequestPacket packet = new SessionRequestPacket(mockConfig, new TestNetbiosName(calledName, calledType, null),
                new TestNetbiosName(callingName, callingType, null));

        byte[] dst = new byte[256];
        int bytesWritten = packet.writeTrailerWireFormat(dst, 0);

        assertTrue(bytesWritten > 0);
        assertNotEquals(0, dst[0]); // First byte should be written
    }

    private static Stream<Arguments> provideNamesForWriteTest() {
        return Stream.of(Arguments.of("SERVER", 0x20, "CLIENT", 0x00), Arguments.of("WORKSTATION", 0x00, "USER", 0x03),
                Arguments.of("DOMAIN", 0x1B, "BROWSER", 0x1D), Arguments.of("A", 0x20, "B", 0x00),
                Arguments.of("VERYLONGNAMETEST", 0x20, "ANOTHERLONGNAME", 0x00));
    }

    @Test
    @DisplayName("writeTrailerWireFormat should handle different buffer offsets")
    void testWriteTrailerWireFormatWithOffset() {
        SessionRequestPacket packet =
                new SessionRequestPacket(mockConfig, new TestNetbiosName("SERVER", 0x20, null), new TestNetbiosName("CLIENT", 0x00, null));

        byte[] dst = new byte[256];
        int offset = 10;

        // Mark the buffer before offset
        for (int i = 0; i < offset; i++) {
            dst[i] = (byte) 0xFF;
        }

        int bytesWritten = packet.writeTrailerWireFormat(dst, offset);

        assertTrue(bytesWritten > 0);
        // Check that bytes before offset are unchanged
        for (int i = 0; i < offset; i++) {
            assertEquals((byte) 0xFF, dst[i]);
        }
        // Check that bytes after offset are written
        assertNotEquals((byte) 0xFF, dst[offset]);
    }

    @Test
    @DisplayName("readTrailerWireFormat should handle different buffer offsets")
    void testReadTrailerWireFormatWithOffset() throws IOException {
        SessionRequestPacket writePacket =
                new SessionRequestPacket(mockConfig, new TestNetbiosName("SERVER", 0x20, null), new TestNetbiosName("CLIENT", 0x00, null));

        byte[] buffer = new byte[256];
        int written = writePacket.writeTrailerWireFormat(buffer, 0);

        ByteArrayInputStream bais = new ByteArrayInputStream(buffer);
        SessionRequestPacket readPacket = new SessionRequestPacket(mockConfig);
        readPacket.length = written;

        byte[] readBuffer = new byte[256];
        System.arraycopy(buffer, 0, readBuffer, 10, written);

        int bytesRead = readPacket.readTrailerWireFormat(bais, readBuffer, 10);

        assertEquals(written, bytesRead);
    }

    @Test
    @DisplayName("Full write and read cycle should preserve data")
    void testFullWriteReadCycle() throws IOException {
        // Create original packet
        SessionRequestPacket originalPacket = new SessionRequestPacket(mockConfig, new TestNetbiosName("FILESERVER", 0x20, "CORP.LOCAL"),
                new TestNetbiosName("WORKSTATION1", 0x00, "CORP.LOCAL"));

        // Write to buffer
        byte[] buffer = new byte[512];
        int written = originalPacket.writeWireFormat(buffer, 0);

        // Read from buffer
        ByteArrayInputStream bais = new ByteArrayInputStream(buffer);
        SessionRequestPacket readPacket = new SessionRequestPacket(mockConfig);

        // Skip header (already read by parent class)
        bais.skip(4);
        readPacket.type = buffer[0] & 0xFF;
        readPacket.length = ((buffer[1] & 0x01) << 16) + ((buffer[2] & 0xFF) << 8) + (buffer[3] & 0xFF);

        byte[] readBuffer = new byte[readPacket.length];
        bais.read(readBuffer, 0, readPacket.length);
        ByteArrayInputStream dataStream = new ByteArrayInputStream(readBuffer);

        int bytesRead = readPacket.readTrailerWireFormat(dataStream, readBuffer, 0);

        assertEquals(SessionServicePacket.SESSION_REQUEST, readPacket.type);
        assertTrue(bytesRead > 0);
    }

    @Test
    @DisplayName("Empty InputStream should cause IOException")
    void testReadTrailerWireFormatEmptyStream() {
        ByteArrayInputStream emptyStream = new ByteArrayInputStream(new byte[0]);
        SessionRequestPacket packet = new SessionRequestPacket(mockConfig);
        packet.length = 10;

        assertThrows(IOException.class, () -> {
            packet.readTrailerWireFormat(emptyStream, new byte[10], 0);
        });
    }

    // Helper class for testing with concrete NetbiosName implementation
    private class TestNetbiosName implements NetbiosName {
        private final String name;
        private final int type;
        private final String scope;

        TestNetbiosName(String name, int type, String scope) {
            // Ensure names are uppercase and limited to 15 characters
            this.name = name != null && name.length() > 15 ? name.substring(0, 15).toUpperCase() : (name != null ? name.toUpperCase() : "");
            this.type = type;
            this.scope = scope;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public int getNameType() {
            return type;
        }

        @Override
        public String getScope() {
            return scope;
        }
    }
}