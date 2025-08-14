package jcifs.internal.smb1;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Date;
import java.util.TimeZone;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.internal.smb1.com.SmbComReadAndXResponse;
import jcifs.internal.smb1.trans.nt.SmbComNtCancel;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.NtlmPasswordAuthenticator;
import jcifs.smb.SmbException;
import jcifs.smb.SmbTransportInternal;

/**
 * Unit tests for SMB1SigningDigest
 */
public class SMB1SigningDigestTest {

    @Mock
    private SmbTransportInternal mockTransport;

    @Mock
    private CIFSContext mockContext;

    @Mock
    private Configuration mockConfig;

    @Mock
    private NtlmPasswordAuthenticator mockAuth;

    @Mock
    private ServerMessageBlock mockRequest;

    @Mock
    private ServerMessageBlock mockResponse;

    @Mock
    private TimeZone mockTimeZone;

    private byte[] testMacSigningKey;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testMacSigningKey = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    }

    @Test
    @DisplayName("Test constructor with MAC signing key and bypass flag")
    void testConstructorWithBypass() {
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey, true);
        assertNotNull(digest);
        assertTrue(digest.toString().contains("MacSigningKey="));
    }

    @Test
    @DisplayName("Test constructor with MAC signing key, bypass flag and initial sequence")
    void testConstructorWithBypassAndInitialSequence() {
        int initialSequence = 100;
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey, true, initialSequence);
        assertNotNull(digest);
    }

    @Test
    @DisplayName("Test constructor with MAC signing key only (Kerberos mode)")
    void testConstructorKerberosMode() {
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey);
        assertNotNull(digest);
    }

    @Test
    @DisplayName("Test constructor with MAC signing key and initial sequence")
    void testConstructorWithInitialSequence() {
        int initialSequence = 50;
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey, initialSequence);
        assertNotNull(digest);
    }

    @Test
    @DisplayName("Test constructor with transport and auth - LM compatibility 0")
    void testConstructorWithTransportLMCompat0() throws Exception {
        setupTransportMocks(0);

        SMB1SigningDigest digest = new SMB1SigningDigest(mockTransport, mockAuth);
        assertNotNull(digest);
    }

    @Test
    @DisplayName("Test constructor with transport and auth - LM compatibility 1")
    void testConstructorWithTransportLMCompat1() throws Exception {
        setupTransportMocks(1);

        SMB1SigningDigest digest = new SMB1SigningDigest(mockTransport, mockAuth);
        assertNotNull(digest);
    }

    @Test
    @DisplayName("Test constructor with transport and auth - LM compatibility 3")
    void testConstructorWithTransportLMCompat3() throws Exception {
        setupTransportMocks(3);

        SMB1SigningDigest digest = new SMB1SigningDigest(mockTransport, mockAuth);
        assertNotNull(digest);
    }

    @Test
    @DisplayName("Test constructor with transport and auth - LM compatibility 5")
    void testConstructorWithTransportLMCompat5() throws Exception {
        setupTransportMocks(5);

        SMB1SigningDigest digest = new SMB1SigningDigest(mockTransport, mockAuth);
        assertNotNull(digest);
    }

    @Test
    @DisplayName("Test constructor with transport throws SmbException on error")
    void testConstructorWithTransportThrowsException() throws Exception {
        when(mockTransport.getContext()).thenReturn(mockContext);
        when(mockContext.getConfig()).thenReturn(mockConfig);
        when(mockConfig.getLanManCompatibility()).thenReturn(3);
        when(mockTransport.getServerEncryptionKey()).thenThrow(new RuntimeException("Test exception"));

        assertThrows(SmbException.class, () -> new SMB1SigningDigest(mockTransport, mockAuth));
    }

    @Test
    @DisplayName("Test update method with valid data")
    void testUpdateWithValidData() {
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey);
        byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        assertDoesNotThrow(() -> digest.update(data, 0, data.length));
    }

    @Test
    @DisplayName("Test update method with zero length")
    void testUpdateWithZeroLength() {
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey);
        byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        // Should return immediately without processing
        assertDoesNotThrow(() -> digest.update(data, 0, 0));
    }

    @Test
    @DisplayName("Test digest method")
    void testDigest() {
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey);
        byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        digest.update(data, 0, data.length);

        byte[] result = digest.digest();
        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    @Test
    @DisplayName("Test sign method with normal request")
    void testSignNormalRequest() {
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey, false, 10);
        byte[] data = new byte[100];

        when(mockRequest.getCommand()).thenReturn((int) ServerMessageBlock.SMB_COM_WRITE);

        digest.sign(data, 0, data.length, mockRequest, mockResponse);

        verify(mockRequest).setSignSeq(10);
        verify(mockResponse).setSignSeq(11);
    }

    @Test
    @DisplayName("Test sign method with bypass enabled")
    void testSignWithBypass() {
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey, true, 10);
        byte[] data = new byte[100];

        digest.sign(data, 0, data.length, mockRequest, mockResponse);

        // Check if BSRSPYL signature is written
        byte[] expectedSignature = "BSRSPYL ".getBytes();
        byte[] actualSignature = new byte[8];
        System.arraycopy(data, SmbConstants.SIGNATURE_OFFSET, actualSignature, 0, 8);
        assertArrayEquals(expectedSignature, actualSignature);
    }

    @Test
    @DisplayName("Test sign method with SmbComNtCancel request")
    void testSignWithNtCancelRequest() {
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey, false, 10);
        byte[] data = new byte[100];

        SmbComNtCancel cancelRequest = mock(SmbComNtCancel.class);

        digest.sign(data, 0, data.length, cancelRequest, null);

        verify(cancelRequest).setSignSeq(10);
        // Sequence should increment by 1 for cancel requests
    }

    @Test
    @DisplayName("Test sign method with null response")
    void testSignWithNullResponse() {
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey, false, 10);
        byte[] data = new byte[100];

        assertDoesNotThrow(() -> digest.sign(data, 0, data.length, mockRequest, null));

        verify(mockRequest).setSignSeq(10);
    }

    @Test
    @DisplayName("Test verify method with valid signature")
    void testVerifyWithValidSignature() {
        // Create digest for signing
        SMB1SigningDigest signDigest = new SMB1SigningDigest(testMacSigningKey, false, 10);
        byte[] data = new byte[100];

        // Prepare mock request
        when(mockRequest.getFlags2()).thenReturn(SmbConstants.FLAGS2_SECURITY_SIGNATURES);
        when(mockRequest.getSignSeq()).thenReturn(10);
        when(mockRequest.getCommand()).thenReturn((int) ServerMessageBlock.SMB_COM_WRITE);
        when(mockRequest.getLength()).thenReturn(100);

        // Sign the data
        signDigest.sign(data, 0, data.length, mockRequest, null);

        // Create a new digest for verification with same key
        SMB1SigningDigest verifyDigest = new SMB1SigningDigest(testMacSigningKey);

        // Verify should return false when signature is correct (no error)
        // The code returns true on line 281 when signatures DON'T match
        boolean result = verifyDigest.verify(data, 0, data.length, 0, mockRequest);

        // The verification should succeed (return false) since we're using the same key
        assertFalse(result);
    }

    @Test
    @DisplayName("Test verify method with unsigned response")
    void testVerifyWithUnsignedResponse() {
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey);
        byte[] data = new byte[100];

        when(mockRequest.getFlags2()).thenReturn(0); // No signature flag

        boolean result = digest.verify(data, 0, data.length, 0, mockRequest);
        assertFalse(result); // Should return false for unsigned response
    }

    @Test
    @DisplayName("Test verify method with SmbComReadAndXResponse")
    void testVerifyWithReadAndXResponse() {
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey);
        byte[] data = new byte[100];
        byte[] readData = new byte[50];

        SmbComReadAndXResponse readResponse = mock(SmbComReadAndXResponse.class);
        when(readResponse.getFlags2()).thenReturn(SmbConstants.FLAGS2_SECURITY_SIGNATURES);
        when(readResponse.getSignSeq()).thenReturn(10);
        when(readResponse.getCommand()).thenReturn((int) ServerMessageBlock.SMB_COM_READ_ANDX);
        when(readResponse.getLength()).thenReturn(100);
        when(readResponse.getDataLength()).thenReturn(50);
        when(readResponse.getData()).thenReturn(readData);
        when(readResponse.getOffset()).thenReturn(0);

        boolean result = digest.verify(data, 0, data.length, 0, readResponse);
        assertTrue(result); // Signature mismatch expected
    }

    @Test
    @DisplayName("Test verify method with invalid signature")
    void testVerifyWithInvalidSignature() {
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey);
        byte[] data = new byte[100];

        // Set invalid signature
        for (int i = 0; i < 8; i++) {
            data[SmbConstants.SIGNATURE_OFFSET + i] = (byte) 0xFF;
        }

        when(mockRequest.getFlags2()).thenReturn(SmbConstants.FLAGS2_SECURITY_SIGNATURES);
        when(mockRequest.getSignSeq()).thenReturn(10);
        when(mockRequest.getCommand()).thenReturn((int) ServerMessageBlock.SMB_COM_WRITE);
        when(mockRequest.getLength()).thenReturn(100);

        boolean result = digest.verify(data, 0, data.length, 0, mockRequest);
        assertTrue(result); // Should return true for signature mismatch
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() {
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey);
        String result = digest.toString();

        assertNotNull(result);
        assertTrue(result.startsWith("MacSigningKey="));
        assertTrue(result.contains("0102030405060708090A0B0C0D0E0F10"));
    }

    @Test
    @DisplayName("Test writeUTime with zero time")
    void testWriteUTimeWithZeroTime() {
        byte[] dst = new byte[4];

        SMB1SigningDigest.writeUTime(mockConfig, 0L, dst, 0);

        assertEquals((byte) 0xFF, dst[0]);
        assertEquals((byte) 0xFF, dst[1]);
        assertEquals((byte) 0xFF, dst[2]);
        assertEquals((byte) 0xFF, dst[3]);
    }

    @Test
    @DisplayName("Test writeUTime with max time")
    void testWriteUTimeWithMaxTime() {
        byte[] dst = new byte[4];

        SMB1SigningDigest.writeUTime(mockConfig, 0xFFFFFFFFFFFFFFFFL, dst, 0);

        assertEquals((byte) 0xFF, dst[0]);
        assertEquals((byte) 0xFF, dst[1]);
        assertEquals((byte) 0xFF, dst[2]);
        assertEquals((byte) 0xFF, dst[3]);
    }

    @Test
    @DisplayName("Test writeUTime with DST scenarios")
    void testWriteUTimeWithDST() {
        when(mockConfig.getLocalTimezone()).thenReturn(mockTimeZone);

        byte[] dst = new byte[4];
        long testTime = System.currentTimeMillis();

        // Test when both current time and test time are in DST
        when(mockTimeZone.inDaylightTime(any(Date.class))).thenReturn(true);
        SMB1SigningDigest.writeUTime(mockConfig, testTime, dst, 0);

        int expectedSeconds = (int) (testTime / 1000L);
        int actualSeconds = SMBUtil.readInt4(dst, 0);
        assertEquals(expectedSeconds, actualSeconds);

        // Test when current time is in DST but test time is not
        when(mockTimeZone.inDaylightTime(any(Date.class))).thenReturn(true) // current time
                .thenReturn(false); // test time
        SMB1SigningDigest.writeUTime(mockConfig, testTime, dst, 0);

        expectedSeconds = (int) ((testTime - 3600000) / 1000L);
        actualSeconds = SMBUtil.readInt4(dst, 0);
        assertEquals(expectedSeconds, actualSeconds);
    }

    @Test
    @DisplayName("Test writeUTime when not in DST")
    void testWriteUTimeNotInDST() {
        when(mockConfig.getLocalTimezone()).thenReturn(mockTimeZone);

        byte[] dst = new byte[4];
        long testTime = System.currentTimeMillis();

        // Test when neither current time nor test time are in DST
        when(mockTimeZone.inDaylightTime(any(Date.class))).thenReturn(false);
        SMB1SigningDigest.writeUTime(mockConfig, testTime, dst, 0);

        int expectedSeconds = (int) (testTime / 1000L);
        int actualSeconds = SMBUtil.readInt4(dst, 0);
        assertEquals(expectedSeconds, actualSeconds);

        // Test when current time is not in DST but test time is
        when(mockTimeZone.inDaylightTime(any(Date.class))).thenReturn(false) // current time
                .thenReturn(true); // test time
        SMB1SigningDigest.writeUTime(mockConfig, testTime, dst, 0);

        expectedSeconds = (int) ((testTime + 3600000) / 1000L);
        actualSeconds = SMBUtil.readInt4(dst, 0);
        assertEquals(expectedSeconds, actualSeconds);
    }

    @Test
    @DisplayName("Test multiple update and digest cycles")
    void testMultipleUpdateDigestCycles() {
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey);

        // First cycle
        byte[] data1 = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        digest.update(data1, 0, data1.length);
        byte[] result1 = digest.digest();
        assertNotNull(result1);

        // Second cycle
        byte[] data2 = new byte[] { 0x05, 0x06, 0x07, 0x08 };
        digest.update(data2, 0, data2.length);
        byte[] result2 = digest.digest();
        assertNotNull(result2);

        // Results should be different due to different input
        assertNotEquals(result1[0], result2[0]);
    }

    @Test
    @DisplayName("Test sign sequence increment for normal requests")
    void testSignSequenceIncrementNormal() {
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey, false, 100);
        byte[] data = new byte[100];

        // First sign
        digest.sign(data, 0, data.length, mockRequest, mockResponse);
        verify(mockRequest).setSignSeq(100);
        verify(mockResponse).setSignSeq(101);

        // Second sign - sequence should have incremented by 2
        ServerMessageBlock mockRequest2 = mock(ServerMessageBlock.class);
        ServerMessageBlock mockResponse2 = mock(ServerMessageBlock.class);
        digest.sign(data, 0, data.length, mockRequest2, mockResponse2);
        verify(mockRequest2).setSignSeq(102);
        verify(mockResponse2).setSignSeq(103);
    }

    @Test
    @DisplayName("Test partial update")
    void testPartialUpdate() {
        SMB1SigningDigest digest = new SMB1SigningDigest(testMacSigningKey);
        byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

        // Update with partial data
        digest.update(data, 2, 4); // Only update with bytes at index 2-5
        byte[] result = digest.digest();

        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    // Helper method to setup transport mocks
    private void setupTransportMocks(int lmCompatibility) throws Exception {
        byte[] serverEncryptionKey = new byte[8];
        byte[] unicodeHash = new byte[24];

        when(mockTransport.getContext()).thenReturn(mockContext);
        when(mockContext.getConfig()).thenReturn(mockConfig);
        when(mockConfig.getLanManCompatibility()).thenReturn(lmCompatibility);
        when(mockTransport.getServerEncryptionKey()).thenReturn(serverEncryptionKey);

        if (lmCompatibility == 3 || lmCompatibility == 4 || lmCompatibility == 5) {
            // For LM compatibility 3-5, only 16 bytes are used
            doAnswer(invocation -> {
                byte[] dest = invocation.getArgument(2);
                int offset = invocation.getArgument(3);
                System.arraycopy(new byte[16], 0, dest, offset, 16);
                return null;
            }).when(mockAuth).getUserSessionKey(eq(mockContext), eq(serverEncryptionKey), any(byte[].class), eq(0));
        } else {
            // For LM compatibility 0-2, 40 bytes are used
            doAnswer(invocation -> {
                byte[] dest = invocation.getArgument(2);
                int offset = invocation.getArgument(3);
                System.arraycopy(new byte[16], 0, dest, offset, 16);
                return null;
            }).when(mockAuth).getUserSessionKey(eq(mockContext), eq(serverEncryptionKey), any(byte[].class), eq(0));

            when(mockAuth.getUnicodeHash(mockContext, serverEncryptionKey)).thenReturn(unicodeHash);
        }
    }
}
