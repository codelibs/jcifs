package jcifs.internal.smb2.session;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.util.SMBUtil;
import jcifs.internal.smb2.Smb2Constants;

@ExtendWith(MockitoExtension.class)
class Smb2LogoffRequestTest {

    @Mock
    Configuration configuration;

    @Mock
    CIFSContext cifsContext;

    // Helper to create a fresh request under test
    private Smb2LogoffRequest newRequest() {
        return new Smb2LogoffRequest(configuration);
    }

    @Test
    @DisplayName("size() returns 8-byte aligned value (header + 4)")
    void size_returnsAlignedValue() {
        // Arrange
        Smb2LogoffRequest req = newRequest();
        int base = Smb2Constants.SMB2_HEADER_LENGTH + 4; // structure size
        int expected = ((base + 7) / 8) * 8; // expected 8-byte alignment

        // Act
        int actual = req.size();

        // Assert
        assertEquals(expected, actual, "size() must be 8-byte aligned");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 5})
    @DisplayName("writeBytesWireFormat writes StructureSize=4 and Reserved=0 at given offset")
    void writeBytesWireFormat_writesExpectedValuesAtOffset(int offset) {
        // Arrange
        Smb2LogoffRequest req = newRequest();
        byte[] buf = new byte[offset + 8]; // extra space for safety

        // Act
        int written = req.writeBytesWireFormat(buf, offset);

        // Assert: should write exactly 4 bytes
        assertEquals(4, written, "Should report 4 bytes written");
        // StructureSize (2 bytes, LE) == 4
        assertEquals(4, SMBUtil.readInt2(buf, offset));
        // Reserved (2 bytes, LE) == 0
        assertEquals(0, SMBUtil.readInt2(buf, offset + 2));
    }

    @Test
    @DisplayName("writeBytesWireFormat throws when buffer too small")
    void writeBytesWireFormat_throwsIfInsufficientSpace() {
        // Arrange
        Smb2LogoffRequest req = newRequest();
        byte[] tiny = new byte[3]; // less than 4 bytes available

        // Act/Assert
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> req.writeBytesWireFormat(tiny, 0));
    }

    @Test
    @DisplayName("writeBytesWireFormat throws with negative index")
    void writeBytesWireFormat_throwsIfNegativeIndex() {
        // Arrange
        Smb2LogoffRequest req = newRequest();
        byte[] buf = new byte[4];

        // Act/Assert
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> req.writeBytesWireFormat(buf, -1));
    }

    @Test
    @DisplayName("readBytesWireFormat returns 0 and tolerates null buffer")
    void readBytesWireFormat_returnsZeroEvenWithNull() {
        // Arrange
        Smb2LogoffRequest req = newRequest();

        // Act
        int resultWithNull = req.readBytesWireFormat(null, 0);
        int resultWithData = req.readBytesWireFormat(new byte[] {1,2,3}, 1);

        // Assert
        assertEquals(0, resultWithNull, "Should return 0 for null buffer");
        assertEquals(0, resultWithData, "Should return 0 regardless of input data");
    }

    @Nested
    class CreateResponseTests {

        @Test
        @DisplayName("createResponse returns Smb2LogoffResponse and requests CIFSContext config")
        void createResponse_happyPath() {
            // Arrange
            when(cifsContext.getConfig()).thenReturn(configuration);
            Smb2LogoffRequest req = newRequest();

            // Act
            Smb2LogoffResponse resp = req.createResponse(cifsContext, req);

            // Assert
            assertNotNull(resp, "Response should be created");
            assertTrue(resp instanceof Smb2LogoffResponse, "Response type should be Smb2LogoffResponse");
            verify(cifsContext, times(1)).getConfig();
            verifyNoMoreInteractions(cifsContext);
        }

        @Test
        @DisplayName("createResponse throws NullPointerException when CIFSContext is null")
        void createResponse_nullContext_throws() {
            // Arrange
            Smb2LogoffRequest req = newRequest();

            // Act/Assert
            assertThrows(NullPointerException.class, () -> req.createResponse(null, req));
        }

        @Test
        @DisplayName("createResponse tolerates null request parameter")
        void createResponse_nullRequest_ok() {
            // Arrange
            when(cifsContext.getConfig()).thenReturn(configuration);
            Smb2LogoffRequest req = newRequest();

            // Act
            Smb2LogoffResponse resp = req.createResponse(cifsContext, null);

            // Assert
            assertNotNull(resp, "Response should be created even if req is null");
            verify(cifsContext, times(1)).getConfig();
            verifyNoMoreInteractions(cifsContext);
        }
    }
}

