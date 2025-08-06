/*
 * Copyright 2024 The JCIFS Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,

 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package jcifs.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.UnsupportedEncodingException;
import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import jcifs.CIFSContext;
import jcifs.DialectVersion;
import jcifs.SmbConstants;
import jcifs.config.BaseConfiguration;
import jcifs.context.BaseContext;
import jcifs.internal.SmbNegotiationRequest;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.util.Hexdump;

public class SmbComNegotiateResponseTest {

    @Mock
    private CIFSContext mockContext;

    private SmbComNegotiateResponse response;

    @BeforeEach
    public void setUp() {
        BaseConfiguration config = new BaseConfiguration(false);
        mockContext = new BaseContext(config);
        response = new SmbComNegotiateResponse(mockContext);
    }

    @Test
    public void testConstructor() {
        assertNotNull(response);
        assertEquals(DialectVersion.SMB1, response.getSelectedDialect());
    }

    @Test
    public void testReadParameterWordsWireFormat() {
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
        ServerMessageBlock.writeTime(time, buffer, bufferIndex);
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
    public void testReadBytesWireFormatWithoutExtendedSecurity() throws UnsupportedEncodingException {
        response.getServerData().scapabilities = 0;
        response.getServerData().encryptionKeyLength = 8;
        response.byteCount = 8 + "DOMAIN".getBytes("UTF-16LE").length;
        byte[] buffer = new byte[response.byteCount];
        int bufferIndex = 0;
        byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        System.arraycopy(key, 0, buffer, bufferIndex, key.length);
        bufferIndex += key.length;
        byte[] domainBytes = "DOMAIN".getBytes("UTF-16LE");
        System.arraycopy(domainBytes, 0, buffer, bufferIndex, domainBytes.length);

        response.readBytesWireFormat(buffer, 0);

        assertArrayEquals(key, response.getServerData().encryptionKey);
        assertEquals("DOMAIN", response.getServerData().oemDomainName);
    }

    @Test
    public void testReadBytesWireFormatWithExtendedSecurity() {
        response.getServerData().scapabilities = SmbConstants.CAP_EXTENDED_SECURITY;
        response.byteCount = 16 + 10; // guid + token
        byte[] buffer = new byte[response.byteCount];
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
    public void testIsValid() {
        SmbNegotiationRequest request = mock(SmbNegotiationRequest.class);
        when(request.isSigningEnforced()).thenReturn(true);
        response.getServerData().signaturesEnabled = true;

        assertTrue(response.isValid(mockContext, request));
        assertTrue(response.isSigningNegotiated());
        assertTrue((response.getNegotiatedFlags2() & SmbConstants.FLAGS2_SECURITY_SIGNATURES) != 0);
    }

    @Test
    public void testIsValidWithUnicode() {
        SmbNegotiationRequest request = mock(SmbNegotiationRequest.class);
        response.getServerData().scapabilities = SmbConstants.CAP_UNICODE;

        assertTrue(response.isValid(mockContext, request));
        assertTrue(response.isUseUnicode());
        assertTrue((response.getNegotiatedCapabilities() & SmbConstants.CAP_UNICODE) != 0);
    }

    @Test
    public void testIsValidWithInvalidDialect() {
        SmbNegotiationRequest request = mock(SmbNegotiationRequest.class);
        response.setDialectIndex(11);
        assertFalse(response.isValid(mockContext, request));
    }

    @Test
    public void testToString() {
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
        response.byteCount = 8;
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
}
