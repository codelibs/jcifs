package org.codelibs.jcifs.smb.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.util.Date;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.config.BaseConfiguration;
import org.codelibs.jcifs.smb.context.BaseContext;
import org.codelibs.jcifs.smb.internal.SmbNegotiationRequest;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.Hexdump;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

public class SmbComNegotiateResponseTest {

    @Mock
    private CIFSContext mockContext;

    private SmbComNegotiateResponse response;

    @BeforeEach
    public void setUp() {
        try {
            BaseConfiguration config = new BaseConfiguration(false);
            mockContext = new BaseContext(config);
            response = new SmbComNegotiateResponse(mockContext);
        } catch (Exception e) {
            throw new RuntimeException("Failed to set up test", e);
        }
    }

    @Test
    @DisplayName("Verify constructor initializes response with correct dialect")
    public void shouldInitializeWithCorrectDialect() {
        assertNotNull(response);
        assertEquals(DialectVersion.SMB1, response.getSelectedDialect());
    }

    @Test
    @DisplayName("Verify readParameterWordsWireFormat parses negotiate response parameters")
    public void shouldParseNegotiateResponseParameters() {
        byte[] buffer = new byte[34];
        int bufferIndex = 0;

        // dialectIndex
        buffer[bufferIndex++] = 5;
        buffer[bufferIndex++] = 0;
        // securityMode
        buffer[bufferIndex++] = 0x03;
        // maxMpxCount
        buffer[bufferIndex++] = 50;
        buffer[bufferIndex++] = 0;
        // maxNumberVcs
        buffer[bufferIndex++] = 1;
        buffer[bufferIndex++] = 0;
        // maxBufferSize
        buffer[bufferIndex++] = (byte) 0x00;
        buffer[bufferIndex++] = (byte) 0x40;
        buffer[bufferIndex++] = 0;
        buffer[bufferIndex++] = 0;
        // maxRawSize
        buffer[bufferIndex++] = (byte) 0x00;
        buffer[bufferIndex++] = (byte) 0x10;
        buffer[bufferIndex++] = 0;
        buffer[bufferIndex++] = 0;
        // sessionKey
        buffer[bufferIndex++] = 1;
        buffer[bufferIndex++] = 2;
        buffer[bufferIndex++] = 3;
        buffer[bufferIndex++] = 4;
        // capabilities
        buffer[bufferIndex++] = (byte) 0x80;
        buffer[bufferIndex++] = 0;
        buffer[bufferIndex++] = 0;
        buffer[bufferIndex++] = 0;
        // serverTime
        long time = new Date().getTime();
        SMBUtil.writeTime(time, buffer, bufferIndex);
        bufferIndex += 8;
        // serverTimeZone
        buffer[bufferIndex++] = (byte) 0x80;
        buffer[bufferIndex++] = (byte) 0xFF;
        // encryptionKeyLength
        buffer[bufferIndex++] = 8;

        int bytesRead = response.readParameterWordsWireFormat(buffer, 0);
        assertEquals(34, bytesRead);
        assertEquals(5, response.getDialectIndex());
        assertTrue(response.getServerData().encryptedPasswords);
        assertEquals(50, response.getServerData().smaxMpxCount);
        assertEquals(1, response.getServerData().maxNumberVcs);
        assertEquals(16384, response.getServerData().maxBufferSize);
        assertEquals(4096, response.getServerData().maxRawSize);
        assertEquals(0x04030201, response.getServerData().sessKey);
        assertEquals(0x80, response.getServerData().scapabilities);
        assertEquals(-128, response.getServerData().serverTimeZone);
        assertEquals(8, response.getServerData().encryptionKeyLength);
    }

    @Test
    @DisplayName("Verify readBytesWireFormat handles non-extended security mode")
    public void shouldHandleNonExtendedSecurityMode() throws UnsupportedEncodingException {
        response.getServerData().scapabilities = 0;
        response.getServerData().encryptionKeyLength = 8;
        // Domain name in OEM encoding (ASCII) with null terminator
        byte[] domainBytes = "DOMAIN\0".getBytes("US-ASCII");
        // Use reflection to set protected byteCount field
        int byteCountValue = 8 + domainBytes.length;
        setByteCount(response, byteCountValue);
        byte[] buffer = new byte[byteCountValue];
        int bufferIndex = 0;
        byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        System.arraycopy(key, 0, buffer, bufferIndex, key.length);
        bufferIndex += key.length;
        System.arraycopy(domainBytes, 0, buffer, bufferIndex, domainBytes.length);

        response.readBytesWireFormat(buffer, 0);

        assertArrayEquals(key, response.getServerData().encryptionKey);
        assertEquals("DOMAIN", response.getServerData().oemDomainName);
    }

    @Test
    @DisplayName("Verify readBytesWireFormat handles Unicode encoding")
    public void shouldHandleUnicodeEncoding() throws UnsupportedEncodingException {
        response.getServerData().scapabilities = SmbConstants.CAP_UNICODE;
        response.getServerData().encryptionKeyLength = 8;
        // Set Unicode flag to use Unicode encoding
        setNegotiatedFlags2(response, SmbConstants.FLAGS2_UNICODE);
        // Domain name in Unicode (UTF-16LE) with null terminator
        byte[] domainBytes = "DOMAIN\0".getBytes("UTF-16LE");
        // Use reflection to set protected byteCount field
        int byteCountValue = 8 + domainBytes.length;
        setByteCount(response, byteCountValue);
        byte[] buffer = new byte[byteCountValue];
        int bufferIndex = 0;
        byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        System.arraycopy(key, 0, buffer, bufferIndex, key.length);
        bufferIndex += key.length;
        System.arraycopy(domainBytes, 0, buffer, bufferIndex, domainBytes.length);

        response.readBytesWireFormat(buffer, 0);

        assertArrayEquals(key, response.getServerData().encryptionKey);
        assertEquals("DOMAIN", response.getServerData().oemDomainName);
    }

    @Test
    @DisplayName("Verify readBytesWireFormat handles extended security mode")
    public void shouldHandleExtendedSecurityMode() {
        response.getServerData().scapabilities = SmbConstants.CAP_EXTENDED_SECURITY;
        // Use reflection to set protected byteCount field
        int byteCountValue = 16 + 10; // guid + token
        setByteCount(response, byteCountValue);
        byte[] buffer = new byte[byteCountValue];
        byte[] guid = new byte[16];
        for (int i = 0; i < 16; i++) {
            guid[i] = (byte) i;
        }
        System.arraycopy(guid, 0, buffer, 0, 16);
        byte[] token = new byte[10];
        for (int i = 0; i < 10; i++) {
            token[i] = (byte) (i + 16);
        }
        System.arraycopy(token, 0, buffer, 16, 10);

        response.readBytesWireFormat(buffer, 0);

        assertArrayEquals(guid, response.getServerData().guid);
        assertEquals(10, response.getServerData().encryptionKeyLength);
        assertArrayEquals(token, response.getServerData().encryptionKey);
        assertEquals("", response.getServerData().oemDomainName);
    }

    @Test
    @DisplayName("Verify isValid returns true for valid response with signing")
    public void shouldReturnTrueForValidResponseWithSigning() {
        SmbNegotiationRequest request = mock(SmbNegotiationRequest.class);
        when(request.isSigningEnforced()).thenReturn(true);
        response.getServerData().signaturesEnabled = true;

        assertTrue(response.isValid(mockContext, request));
        assertTrue(response.isSigningNegotiated());
        assertTrue((response.getNegotiatedFlags2() & SmbConstants.FLAGS2_SECURITY_SIGNATURES) != 0);
    }

    @Test
    @DisplayName("Verify isValid handles Unicode capability correctly")
    public void shouldHandleUnicodeCapabilityCorrectly() {
        SmbNegotiationRequest request = mock(SmbNegotiationRequest.class);
        response.getServerData().scapabilities = SmbConstants.CAP_UNICODE;
        // Set some required server data for valid response
        response.getServerData().smaxMpxCount = 1;
        response.getServerData().maxBufferSize = 16384;

        assertTrue(response.isValid(mockContext, request));
        // After negotiation, check if unicode capability is preserved
        assertTrue((response.getNegotiatedCapabilities() & SmbConstants.CAP_UNICODE) != 0);
    }

    @Test
    @DisplayName("Verify isValid returns false for invalid dialect index")
    public void shouldReturnFalseForInvalidDialect() {
        SmbNegotiationRequest request = mock(SmbNegotiationRequest.class);
        // Use reflection to set private dialectIndex field
        setDialectIndex(response, 11);
        assertFalse(response.isValid(mockContext, request));
    }

    @Test
    @DisplayName("Verify toString returns properly formatted response string")
    public void shouldReturnFormattedResponseString() {
        response.getServerData().securityMode = 1;
        response.getServerData().encryptedPasswords = true;
        response.getServerData().smaxMpxCount = 50;
        response.getServerData().maxNumberVcs = 1;
        response.getServerData().maxBufferSize = 16384;
        response.getServerData().maxRawSize = 4096;
        response.getServerData().sessKey = 0x12345678;
        response.getServerData().scapabilities = SmbConstants.CAP_UNICODE;
        response.getServerData().serverTime = new Date().getTime();
        response.getServerData().serverTimeZone = -300;
        response.getServerData().encryptionKeyLength = 8;
        // Use reflection to set protected byteCount field
        setByteCount(response, 8);
        response.getServerData().oemDomainName = "TEST_DOMAIN";

        String result = response.toString();
        assertNotNull(result);
        assertTrue(result.contains("SmbComNegotiateResponse"));
        assertTrue(result.contains("dialectIndex=0"));
        assertTrue(result.contains("securityMode=0x1"));
        assertTrue(result.contains("encryptedPasswords=true"));
        assertTrue(result.contains("maxMpxCount=50"));
        assertTrue(result.contains("maxNumberVcs=1"));
        assertTrue(result.contains("maxBufferSize=16384"));
        assertTrue(result.contains("maxRawSize=4096"));
        assertTrue(result.contains("sessionKey=0x" + Hexdump.toHexString(0x12345678, 8)));
        assertTrue(result.contains("capabilities=0x" + Hexdump.toHexString(SmbConstants.CAP_UNICODE, 8)));
        assertTrue(result.contains("serverTimeZone=-300"));
        assertTrue(result.contains("encryptionKeyLength=8"));
        assertTrue(result.contains("byteCount=8"));
        assertTrue(result.contains("oemDomainName=TEST_DOMAIN"));
    }

    // Helper method to set protected byteCount field using reflection
    private void setByteCount(SmbComNegotiateResponse response, int byteCount) {
        try {
            Field field = response.getClass().getSuperclass().getDeclaredField("byteCount");
            field.setAccessible(true);
            field.set(response, byteCount);
        } catch (Exception e) {
            throw new RuntimeException("Failed to set byteCount field", e);
        }
    }

    // Helper method to set private dialectIndex field using reflection
    private void setDialectIndex(SmbComNegotiateResponse response, int dialectIndex) {
        try {
            Field field = response.getClass().getDeclaredField("dialectIndex");
            field.setAccessible(true);
            field.set(response, dialectIndex);
        } catch (Exception e) {
            throw new RuntimeException("Failed to set dialectIndex field", e);
        }
    }

    // Helper method to set protected negotiatedFlags2 field using reflection
    private void setNegotiatedFlags2(SmbComNegotiateResponse response, int flags2) {
        try {
            Field field = response.getClass().getDeclaredField("negotiatedFlags2");
            field.setAccessible(true);
            field.set(response, flags2);
        } catch (Exception e) {
            throw new RuntimeException("Failed to set negotiatedFlags2 field", e);
        }
    }
}
