/*
 * Copyright 2025 shin-osuke
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
package jcifs.pac.kerberos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.kerberos.KerberosKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.pac.PACDecodingException;
import jcifs.pac.Pac;
import jcifs.pac.PacConstants;
import jcifs.pac.PacMac;
import jcifs.pac.PacSignature;

@ExtendWith(MockitoExtension.class)
class KerberosPacAuthDataTest {

    @Mock
    private KerberosKey kerberosKey;

    private Map<Integer, KerberosKey> keys;

    @BeforeEach
    void setUp() {
        keys = new HashMap<>();
    }

    // Test case for successful PAC decoding and instantiation
    @Test
    void testConstructorSuccess() throws PACDecodingException, IOException, GeneralSecurityException {
        // A minimal valid PAC is complex to construct.
        // This test builds a PAC with required structures (LogonInfo, ServerSig, KdcSig)
        // and calculates a valid signature to ensure the constructor succeeds.

        // 1. Define PAC structure and content
        byte[] logonInfoData = new byte[80]; // Dummy logon info
        int signatureType = PacSignature.HMAC_SHA1_96_AES256;
        byte[] keyBytes = new byte[32]; // 256-bit key for AES256
        KerberosKey kdcKey = new KerberosKey(null, keyBytes, signatureType, 1);
        keys.put(PacSignature.ETYPE_AES256_CTS_HMAC_SHA1_96, kdcKey);

        // 2. Build the PAC buffer without signatures first
        byte[] pacDataNoSig = buildPac(logonInfoData, new byte[12], new byte[12]);

        // 3. Calculate the server signature
        byte[] serverChecksum = PacMac.calculateMac(signatureType, keys, pacDataNoSig);

        // 4. Calculate the KDC signature (here, for simplicity, we reuse the server signature)
        byte[] kdcChecksum = PacMac.calculateMac(signatureType, keys, pacDataNoSig);

        // 5. Build the final PAC with correct signatures
        byte[] finalPacData = buildPac(logonInfoData, serverChecksum, kdcChecksum);

        // 6. Execute and Assert
        KerberosPacAuthData authData = new KerberosPacAuthData(finalPacData, keys);
        assertNotNull(authData.getPac());
        assertNotNull(authData.getPac().getLogonInfo());
        assertNotNull(authData.getPac().getServerSignature());
        assertNotNull(authData.getPac().getKdcSignature());
    }

    private byte[] buildPac(byte[] logonInfoData, byte[] serverChecksum, byte[] kdcChecksum) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        int numBuffers = 3;
        long logonInfoOffset = 8L + (numBuffers * 24L); // Header + Buffer Entries
        long serverSigOffset = logonInfoOffset + logonInfoData.length;
        long kdcSigOffset = serverSigOffset + (4 + serverChecksum.length);

        // PAC Header
        dos.writeInt(Integer.reverseBytes(numBuffers)); // cBuffers
        dos.writeInt(Integer.reverseBytes(PacConstants.PAC_VERSION)); // Version

        // Buffer Entries (Type, Size, Offset)
        // Logon Info
        writeBufferEntry(dos, PacConstants.LOGON_INFO, logonInfoData.length, logonInfoOffset);
        // Server Signature
        writeBufferEntry(dos, PacConstants.SERVER_CHECKSUM, 4 + serverChecksum.length, serverSigOffset);
        // KDC Signature
        writeBufferEntry(dos, PacConstants.PRIVSVR_CHECKSUM, 4 + kdcChecksum.length, kdcSigOffset);

        // Buffer Data
        dos.write(logonInfoData);
        writeSignatureBuffer(dos, PacSignature.HMAC_SHA1_96_AES256, serverChecksum);
        writeSignatureBuffer(dos, PacSignature.HMAC_SHA1_96_AES256, kdcChecksum);

        return baos.toByteArray();
    }

    private void writeBufferEntry(DataOutputStream dos, int type, int size, long offset) throws IOException {
        dos.writeInt(Integer.reverseBytes(type));
        dos.writeInt(Integer.reverseBytes(size));
        dos.writeLong(Long.reverseBytes(offset));
    }

    private void writeSignatureBuffer(DataOutputStream dos, int type, byte[] checksum) throws IOException {
        dos.writeInt(Integer.reverseBytes(type));
        dos.write(checksum);
    }


    // Test case for a PAC token that is too short
    @Test
    void testConstructorShortToken() {
        byte[] shortToken = new byte[7];
        PACDecodingException e = assertThrows(PACDecodingException.class, () -> {
            new KerberosPacAuthData(shortToken, keys);
        });
        assertEquals("Empty PAC", e.getMessage());
    }

    // Test case for a PAC with an unrecognized version
    @Test
    void testConstructorWrongVersion() {
        ByteBuffer bb = ByteBuffer.allocate(12);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(1); // cBuffers
        bb.putInt(99); // Invalid Version
        bb.putInt(0);
        byte[] wrongVersionToken = bb.array();

        PACDecodingException e = assertThrows(PACDecodingException.class, () -> {
            new KerberosPacAuthData(wrongVersionToken, keys);
        });
        assertEquals("Unrecognized PAC version 99", e.getMessage());
    }

    // Test case for when required buffers (e.g., LogonInfo) are missing
    @Test
    void testConstructorMissingRequiredBuffers() throws IOException {
         ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // Header: 0 buffers, correct version
        dos.writeInt(Integer.reverseBytes(0));
        dos.writeInt(Integer.reverseBytes(PacConstants.PAC_VERSION));
        byte[] missingBuffersToken = baos.toByteArray();

        PACDecodingException e = assertThrows(PACDecodingException.class, () -> {
            new KerberosPacAuthData(missingBuffersToken, keys);
        });
        assertEquals("Missing required buffers", e.getMessage());
    }

    // Test case for when the PAC signature is invalid
    @Test
    void testConstructorInvalidSignature() throws IOException {
        byte[] logonInfoData = new byte[80];
        byte[] invalidChecksum = new byte[12]; // All zeros, almost certainly wrong

        // Use a real key this time
        byte[] keyBytes = new byte[32];
        for(int i=0; i<keyBytes.length; i++) keyBytes[i] = (byte)i;
        KerberosKey kdcKey = new KerberosKey(null, keyBytes, PacSignature.HMAC_SHA1_96_AES256, 1);
        keys.put(PacSignature.ETYPE_AES256_CTS_HMAC_SHA1_96, kdcKey);

        byte[] pacWithInvalidSig = buildPac(logonInfoData, invalidChecksum, invalidChecksum);

        PACDecodingException e = assertThrows(PACDecodingException.class, () -> {
            new KerberosPacAuthData(pacWithInvalidSig, keys);
        });
        assertEquals("Invalid PAC signature", e.getMessage());
    }

    // Test that the getPac() method returns the created Pac object
    @Test
    void testGetPac() throws PACDecodingException, GeneralSecurityException, IOException {
        // This test reuses the setup from the success test to get a valid Pac object.
        byte[] logonInfoData = new byte[80];
        int signatureType = PacSignature.HMAC_SHA1_96_AES256;
        byte[] keyBytes = new byte[32];
        KerberosKey kdcKey = new KerberosKey(null, keyBytes, signatureType, 1);
        keys.put(PacSignature.ETYPE_AES256_CTS_HMAC_SHA1_96, kdcKey);
        byte[] pacDataNoSig = buildPac(logonInfoData, new byte[12], new byte[12]);
        byte[] serverChecksum = PacMac.calculateMac(signatureType, keys, pacDataNoSig);
        byte[] kdcChecksum = PacMac.calculateMac(signatureType, keys, pacDataNoSig);
        byte[] finalPacData = buildPac(logonInfoData, serverChecksum, kdcChecksum);

        KerberosPacAuthData authData = new KerberosPacAuthData(finalPacData, keys);
        Pac pac = authData.getPac();
        assertNotNull(pac);
    }
}
