package org.codelibs.jcifs.smb.internal.smb2.session;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.BaseTest;
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.impl.NtStatus;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * Tests for Smb2SessionSetupResponse decoding and behavior.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Smb2SessionSetupResponse Tests")
@MockitoSettings(strictness = Strictness.LENIENT)
class Smb2SessionSetupResponseTest extends BaseTest {

    private Smb2SessionSetupResponse newResponse() {
        // Configuration is not used during decode when no signing digest is set
        Configuration cfg = mock(Configuration.class);
        return new Smb2SessionSetupResponse(cfg);
    }

    /**
     * Build a minimal SMB2 header for a response at the given offset.
     * The header is prepared as a synchronous response with server-to-redirector flag.
     */
    private void buildHeader(byte[] buf, int start, int status, int command, long sessionId) {
        System.arraycopy(SMBUtil.SMB2_HEADER, 0, buf, start, SMBUtil.SMB2_HEADER.length);
        // Status at +8
        SMBUtil.writeInt4(status, buf, start + 8);
        // Command at +12
        SMBUtil.writeInt2(command, buf, start + 12);
        // Flags at +16: server-to-redirector
        SMBUtil.writeInt4(0x00000001, buf, start + 16);
        // SessionId at +40 (sync header)
        SMBUtil.writeInt8(sessionId, buf, start + 40);
    }

    /**
     * Build a SESSION_SETUP response body with specified flags and security blob.
     * securityBufferOffset is set relative to header start.
     */
    private void buildSessionSetupBody(byte[] buf, int headerStart, int bodyStart, int sessionFlags, int secBufOffset, byte[] blob) {
        // StructureSize (must be 9)
        SMBUtil.writeInt2(9, buf, bodyStart);
        // SessionFlags at +2
        SMBUtil.writeInt2(sessionFlags, buf, bodyStart + 2);
        // SecurityBufferOffset (+4) and Length (+6)
        SMBUtil.writeInt2(secBufOffset, buf, bodyStart + 4);
        SMBUtil.writeInt2(blob != null ? blob.length : 0, buf, bodyStart + 6);
        if (blob != null && blob.length > 0) {
            int blobStart = headerStart + secBufOffset;
            System.arraycopy(blob, 0, buf, blobStart, blob.length);
        }
    }

    @Test
    @DisplayName("Decode with MORE_PROCESSING_REQUIRED should parse blob and flags")
    void testDecodeMoreProcessingParsesBlobAndFlags() throws Exception {
        Smb2SessionSetupResponse resp = newResponse();

        byte[] buf = new byte[256];
        int headerStart = 0;
        long expectedSessionId = 0x1122334455667788L;
        buildHeader(buf, headerStart, NtStatus.NT_STATUS_MORE_PROCESSING_REQUIRED, 0x0001, expectedSessionId);

        int bodyStart = headerStart + Smb2Constants.SMB2_HEADER_LENGTH;
        byte[] blob = new byte[] { 10, 20, 30, 40, 50 };
        int secBufOffset = Smb2Constants.SMB2_HEADER_LENGTH + 8; // directly after fixed part
        int sessionFlags = Smb2SessionSetupResponse.SMB2_SESSION_FLAGS_IS_GUEST;
        buildSessionSetupBody(buf, headerStart, bodyStart, sessionFlags, secBufOffset, blob);

        int decoded = resp.decode(buf, headerStart);
        assertTrue(decoded > 0, "Decode should return positive length");

        assertEquals(NtStatus.NT_STATUS_MORE_PROCESSING_REQUIRED, resp.getStatus());
        assertArrayEquals(blob, resp.getBlob(), "Security blob should match");
        assertEquals(sessionFlags, resp.getSessionFlags(), "Session flags should decode");
        assertTrue(resp.isLoggedInAsGuest(), "Guest/anonymous should be detected");

        // prepare should propagate session id when received
        CIFSContext mockCtx = mock(CIFSContext.class);
        when(mockCtx.getConfig()).thenReturn(mock(Configuration.class));
        Smb2SessionSetupRequest nextReq = new Smb2SessionSetupRequest(mockCtx, 0, 0, 0L, null);
        assertEquals(0L, nextReq.getSessionId());
        resp.prepare(nextReq);
        assertEquals(expectedSessionId, nextReq.getSessionId(), "prepare() should propagate sessionId");
    }

    @Test
    @DisplayName("Decode with SUCCESS should parse body and non-guest flag")
    void testDecodeSuccessParsesBody() throws Exception {
        Smb2SessionSetupResponse resp = newResponse();

        byte[] buf = new byte[256];
        int headerStart = 0;
        buildHeader(buf, headerStart, NtStatus.NT_STATUS_SUCCESS, 0x0001, 0xCAFEBABECAFEF00DL);

        int bodyStart = headerStart + Smb2Constants.SMB2_HEADER_LENGTH;
        byte[] blob = new byte[] { 1, 2, 3 };
        int secBufOffset = Smb2Constants.SMB2_HEADER_LENGTH + 8;
        int sessionFlags = 0; // not guest/null
        buildSessionSetupBody(buf, headerStart, bodyStart, sessionFlags, secBufOffset, blob);

        resp.decode(buf, headerStart);

        assertArrayEquals(blob, resp.getBlob());
        assertEquals(0, resp.getSessionFlags());
        assertFalse(resp.isLoggedInAsGuest());
    }

    @Test
    @DisplayName("Decode with ACCESS_DENIED should treat as error response")
    void testDecodeErrorResponsePath() throws Exception {
        Smb2SessionSetupResponse resp = newResponse();

        byte[] buf = new byte[256];
        int headerStart = 0;
        buildHeader(buf, headerStart, NtStatus.NT_STATUS_ACCESS_DENIED, 0x0001, 0x0L);

        int bodyStart = headerStart + Smb2Constants.SMB2_HEADER_LENGTH;
        // Error response structure: size(2)=9, errorContextCount(1), reserved(1), bc(4), errorData(bc)
        SMBUtil.writeInt2(9, buf, bodyStart);
        buf[bodyStart + 2] = 0x02; // errorContextCount
        buf[bodyStart + 3] = 0x00; // reserved
        int bc = 4;
        SMBUtil.writeInt4(bc, buf, bodyStart + 4);
        byte[] err = new byte[] { 0x55, 0x66, 0x77, 0x01 };
        System.arraycopy(err, 0, buf, bodyStart + 8, bc);

        int decoded = resp.decode(buf, headerStart);
        assertTrue(decoded > 0);

        // When error path is taken, no blob should be parsed
        assertNull(resp.getBlob(), "Blob should be null on error path");
        assertNotNull(resp.getErrorData(), "Error data should be present");
        assertArrayEquals(err, resp.getErrorData());
    }

    @Test
    @DisplayName("Invalid structure size should throw during decode")
    void testInvalidStructureSizeThrows() {
        Smb2SessionSetupResponse resp = newResponse();

        byte[] buf = new byte[128];
        int headerStart = 0;
        buildHeader(buf, headerStart, NtStatus.NT_STATUS_SUCCESS, 0x0001, 0x0L);

        int bodyStart = headerStart + Smb2Constants.SMB2_HEADER_LENGTH;
        // Wrong structure size (should be 9)
        SMBUtil.writeInt2(8, buf, bodyStart);
        SMBUtil.writeInt2(0, buf, bodyStart + 2);
        SMBUtil.writeInt2(Smb2Constants.SMB2_HEADER_LENGTH + 8, buf, bodyStart + 4);
        SMBUtil.writeInt2(0, buf, bodyStart + 6);

        assertThrows(SMBProtocolDecodingException.class, () -> resp.decode(buf, headerStart));
    }

    @Test
    @DisplayName("Security buffer with forward offset should be parsed correctly")
    void testDecodeWithForwardOffset() throws Exception {
        Smb2SessionSetupResponse resp = newResponse();

        byte[] buf = new byte[256];
        int headerStart = 0;
        buildHeader(buf, headerStart, NtStatus.NT_STATUS_SUCCESS, 0x0001, 0x0L);

        int bodyStart = headerStart + Smb2Constants.SMB2_HEADER_LENGTH;
        byte[] blob = new byte[] { 9, 8, 7, 6 };
        // Place blob further ahead to exercise pad adjustment logic
        int secBufOffset = Smb2Constants.SMB2_HEADER_LENGTH + 16; // beyond current bodyIndex (64+8)
        int sessionFlags = Smb2SessionSetupResponse.SMB2_SESSION_FLAGS_IS_NULL;
        buildSessionSetupBody(buf, headerStart, bodyStart, sessionFlags, secBufOffset, blob);

        resp.decode(buf, headerStart);

        assertArrayEquals(blob, resp.getBlob());
        assertEquals(sessionFlags, resp.getSessionFlags());
        assertTrue(resp.isLoggedInAsGuest(), "Anonymous should be treated as guest login");
    }

    @Test
    @DisplayName("prepare should not set sessionId if not received yet")
    void testPrepareWithoutReceivedDoesNotPropagate() {
        Smb2SessionSetupResponse resp = newResponse();
        // Set a sessionId, but do not mark as received via decode
        resp.setSessionId(0x1234L);

        CIFSContext mockCtx = mock(CIFSContext.class);
        when(mockCtx.getConfig()).thenReturn(mock(Configuration.class));
        Smb2SessionSetupRequest nextReq = new Smb2SessionSetupRequest(mockCtx, 0, 0, 0L, null);
        assertEquals(0L, nextReq.getSessionId());

        resp.prepare(nextReq);
        assertEquals(0L, nextReq.getSessionId(), "SessionId should not be propagated before response is received");
    }

    @Test
    @DisplayName("writeBytesWireFormat should return 0 for response class")
    void testWriteBytesWireFormatReturnsZero() throws Exception {
        Smb2SessionSetupResponse resp = newResponse();
        byte[] dst = new byte[32];
        int written = resp.writeBytesWireFormat(dst, 0);
        assertEquals(0, written);
    }
}
