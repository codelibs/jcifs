/*
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package jcifs.pac;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.kerberos.KerberosKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import jcifs.pac.PACDecodingException;
import jcifs.pac.kerberos.KerberosConstants;

import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;

class PacTest {

    private Map<Integer, KerberosKey> keys;
    private byte[] serverKeyBytes = "serverKey1234567".getBytes();
    private KerberosKey serverKey;

    @BeforeEach
    void setUp() {
        keys = new HashMap<>();
        serverKey = new KerberosKey(null, serverKeyBytes, KerberosConstants.RC4_ENC_TYPE, 1);
        keys.put(KerberosConstants.RC4_ENC_TYPE, serverKey);
    }

    // Helper to build a PAC
    private byte[] buildPac(int version, PacBuffer... buffers) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // Header
        dos.writeInt(buffers.length); // bufferCount
        dos.writeInt(version); // version

        // Buffer descriptors
        long offset = 8 + (buffers.length * 16); // Header size + descriptors size
        for (PacBuffer buffer : buffers) {
            dos.writeInt(buffer.type);
            dos.writeInt(buffer.data.length);
            dos.writeLong(offset);
            buffer.offset = offset;
            offset += buffer.data.length;
            // Align to 8 bytes
            if (offset % 8 != 0) {
                offset += (8 - (offset % 8));
            }
        }

        // Buffer data
        for (PacBuffer buffer : buffers) {
            // Pad to align
            while (baos.size() < buffer.offset) {
                baos.write(0);
            }
            baos.write(buffer.data);
        }

        return baos.toByteArray();
    }

    private static class PacBuffer {
        int type;
        byte[] data;
        long offset;

        PacBuffer(int type, byte[] data) {
            this.type = type;
            this.data = data;
        }
    }

    private byte[] createLogonInfo() throws IOException {
        // Create a minimal valid PAC logon info structure
        // This is a simplified representation for testing
        return new byte[320]; // Minimum size for PAC logon info
    }

    private byte[] createCredentialType() {
        return new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    }

    private byte[] createSignature(int type, byte[] checksum) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(type);
        dos.write(checksum);
        return baos.toByteArray();
    }

    @Test
    void testSuccessfulPacParsing() throws IOException, PACDecodingException, NdrException {
        // Arrange
        byte[] logonInfoData = createLogonInfo();
        byte[] credentialTypeData = createCredentialType();
        byte[] kdcSignatureData = createSignature(KerberosConstants.RC4_ENC_TYPE, new byte[16]);

        // Build PAC without server signature first to calculate checksum
        PacBuffer logonInfoBuffer = new PacBuffer(PacConstants.LOGON_INFO, logonInfoData);
        PacBuffer credentialTypeBuffer = new PacBuffer(PacConstants.CREDENTIAL_TYPE, credentialTypeData);
        PacBuffer kdcSignatureBuffer = new PacBuffer(PacConstants.PRIVSVR_CHECKSUM, kdcSignatureData);
        PacBuffer serverSignatureBuffer = new PacBuffer(PacConstants.SERVER_CHECKSUM, new byte[20]); // Placeholder

        byte[] pacDataForChecksum = buildPac(PacConstants.PAC_VERSION, logonInfoBuffer, credentialTypeBuffer, kdcSignatureBuffer, serverSignatureBuffer);

        // Calculate server checksum
        byte[] checksum = PacMac.calculateMac(KerberosConstants.RC4_ENC_TYPE, keys, pacDataForChecksum);

        // Create actual server signature
        byte[] serverSignatureData = createSignature(KerberosConstants.RC4_ENC_TYPE, checksum);
        serverSignatureBuffer.data = serverSignatureData; // Update with real signature

        // Re-build the final PAC data
        byte[] pacData = buildPac(PacConstants.PAC_VERSION, logonInfoBuffer, credentialTypeBuffer, kdcSignatureBuffer, serverSignatureBuffer);

        // Act
        Pac pac = new Pac(pacData, keys);

        // Assert
        assertNotNull(pac.getLogonInfo());
        // Note: getLogonTime() returns Date, not long
        assertNotNull(pac.getLogonInfo().getLogonTime());
        assertNotNull(pac.getCredentialType());
        // Note: PacCredentialType doesn't have getData() method
        assertNotNull(pac.getServerSignature());
        assertArrayEquals(checksum, pac.getServerSignature().getChecksum());
        assertNotNull(pac.getKdcSignature());
    }

    @Test
    void testEmptyPac() {
        // Arrange
        byte[] emptyData = new byte[8];

        // Act & Assert
        PACDecodingException e = assertThrows(PACDecodingException.class, () -> new Pac(emptyData, keys));
        assertEquals("Empty PAC", e.getMessage());
    }

    @Test
    void testInvalidVersion() throws IOException {
        // Arrange
        byte[] pacData = buildPac(99, new PacBuffer(PacConstants.LOGON_INFO, new byte[1]));

        // Act & Assert
        PACDecodingException e = assertThrows(PACDecodingException.class, () -> new Pac(pacData, keys));
        assertEquals("Unrecognized PAC version 99", e.getMessage());
    }

    @Test
    void testUnalignedBuffer() throws IOException {
        // Arrange
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(1); // bufferCount
        dos.writeInt(PacConstants.PAC_VERSION); // version
        dos.writeInt(PacConstants.LOGON_INFO); // type
        dos.writeInt(1); // size
        dos.writeLong(25); // Unaligned offset (8 + 16 + 1)
        dos.write(new byte[10]);
        byte[] pacData = baos.toByteArray();

        // Act & Assert
        PACDecodingException e = assertThrows(PACDecodingException.class, () -> new Pac(pacData, keys));
        assertEquals("Unaligned buffer 1", e.getMessage());
    }

    @Test
    void testMalformedPac() {
        // Arrange
        byte[] malformedData = new byte[] { 1, 0, 0, 0 }; // Incomplete header

        // Act & Assert
        PACDecodingException e = assertThrows(PACDecodingException.class, () -> new Pac(malformedData, keys));
        assertEquals("Malformed PAC", e.getMessage());
    }

    @Test
    void testMissingRequiredBuffers() throws IOException {
        // Arrange
        PacBuffer logonInfoBuffer = new PacBuffer(PacConstants.LOGON_INFO, createLogonInfo());
        byte[] pacData = buildPac(PacConstants.PAC_VERSION, logonInfoBuffer); // Missing signatures

        // Act & Assert
        // This test expects that PAC validation will fail when required buffers are missing
        assertThrows(PACDecodingException.class, () -> new Pac(pacData, keys));
    }

    @Test
    void testInvalidSignature() throws IOException, NdrException {
        // Arrange
        byte[] logonInfoData = createLogonInfo();
        byte[] credentialTypeData = createCredentialType();
        byte[] kdcSignatureData = createSignature(KerberosConstants.RC4_ENC_TYPE, new byte[16]);
        byte[] invalidServerSignatureData = createSignature(KerberosConstants.RC4_ENC_TYPE, new byte[16]); // Wrong checksum

        PacBuffer logonInfoBuffer = new PacBuffer(PacConstants.LOGON_INFO, logonInfoData);
        PacBuffer credentialTypeBuffer = new PacBuffer(PacConstants.CREDENTIAL_TYPE, credentialTypeData);
        PacBuffer kdcSignatureBuffer = new PacBuffer(PacConstants.PRIVSVR_CHECKSUM, kdcSignatureData);
        PacBuffer serverSignatureBuffer = new PacBuffer(PacConstants.SERVER_CHECKSUM, invalidServerSignatureData);

        byte[] pacData = buildPac(PacConstants.PAC_VERSION, logonInfoBuffer, credentialTypeBuffer, kdcSignatureBuffer, serverSignatureBuffer);

        // Act & Assert
        PACDecodingException e = assertThrows(PACDecodingException.class, () -> new Pac(pacData, keys));
        assertEquals("Invalid PAC signature", e.getMessage());
    }
}
