package jcifs.pac.kerberos;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.kerberos.KerberosKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;

import jcifs.pac.PACDecodingException;
import jcifs.pac.Pac;
import jcifs.pac.PacConstants;
import jcifs.pac.PacLogonInfo;
import jcifs.pac.PacSignature;

class KerberosPacAuthDataTest {

    private Map<Integer, KerberosKey> keys;

    @BeforeEach
    void setUp() {
        keys = new HashMap<>();
    }

    // Test successful PAC creation with mocked Pac construction
    @Test
    void testConstructorSuccess() throws PACDecodingException {
        // Setup key
        byte[] keyBytes = new byte[32];
        KerberosKey kdcKey = new KerberosKey(null, keyBytes, PacSignature.HMAC_SHA1_96_AES256, 1);
        keys.put(PacSignature.ETYPE_AES256_CTS_HMAC_SHA1_96, kdcKey);

        // Mock Pac construction to bypass complex validation
        try (MockedConstruction<Pac> pacMock = Mockito.mockConstruction(Pac.class, (mock, context) -> {
            // Setup mock behavior
            PacLogonInfo mockLogonInfo = Mockito.mock(PacLogonInfo.class);
            PacSignature mockServerSig = Mockito.mock(PacSignature.class);
            PacSignature mockKdcSig = Mockito.mock(PacSignature.class);

            Mockito.when(mock.getLogonInfo()).thenReturn(mockLogonInfo);
            Mockito.when(mock.getServerSignature()).thenReturn(mockServerSig);
            Mockito.when(mock.getKdcSignature()).thenReturn(mockKdcSig);
        })) {

            // Create minimal PAC data
            byte[] pacData = createMinimalPacData();

            // Test constructor
            KerberosPacAuthData authData = new KerberosPacAuthData(pacData, keys);
            assertNotNull(authData.getPac());
            assertNotNull(authData.getPac().getLogonInfo());
            assertNotNull(authData.getPac().getServerSignature());
            assertNotNull(authData.getPac().getKdcSignature());
        }
    }

    // Test exception for empty PAC
    @Test
    void testConstructorEmptyPac() {
        byte[] emptyToken = new byte[0];
        PACDecodingException e = assertThrows(PACDecodingException.class, () -> {
            new KerberosPacAuthData(emptyToken, keys);
        });
        assertTrue(e.getMessage().contains("PAC"));
    }

    // Test exception for short PAC
    @Test
    void testConstructorShortPac() {
        byte[] shortToken = new byte[7];
        PACDecodingException e = assertThrows(PACDecodingException.class, () -> {
            new KerberosPacAuthData(shortToken, keys);
        });
        assertTrue(e.getMessage().contains("PAC"));
    }

    // Test exception for invalid version
    @Test
    void testConstructorInvalidVersion() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // Write header with invalid version
        dos.writeInt(Integer.reverseBytes(1)); // 1 buffer
        dos.writeInt(Integer.reverseBytes(999)); // Invalid version

        // Add minimal buffer entry
        dos.writeInt(Integer.reverseBytes(PacConstants.LOGON_INFO));
        dos.writeInt(Integer.reverseBytes(10));
        dos.writeLong(Long.reverseBytes(100));

        byte[] invalidVersionPac = baos.toByteArray();

        PACDecodingException e = assertThrows(PACDecodingException.class, () -> {
            new KerberosPacAuthData(invalidVersionPac, keys);
        });
        assertTrue(e.getMessage().contains("PAC"));
    }

    // Test exception for missing buffers
    @Test
    void testConstructorMissingBuffers() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // Write header with no buffers
        dos.writeInt(Integer.reverseBytes(0));
        dos.writeInt(Integer.reverseBytes(PacConstants.PAC_VERSION));

        byte[] noBufPac = baos.toByteArray();

        PACDecodingException e = assertThrows(PACDecodingException.class, () -> {
            new KerberosPacAuthData(noBufPac, keys);
        });
        assertTrue(e.getMessage().contains("PAC"));
    }

    // Test getPac() returns the Pac object  
    @Test
    void testGetPac() throws PACDecodingException {
        byte[] keyBytes = new byte[32];
        KerberosKey kdcKey = new KerberosKey(null, keyBytes, PacSignature.HMAC_SHA1_96_AES256, 1);
        keys.put(PacSignature.ETYPE_AES256_CTS_HMAC_SHA1_96, kdcKey);

        try (MockedConstruction<Pac> pacMock = Mockito.mockConstruction(Pac.class)) {
            byte[] pacData = createMinimalPacData();
            KerberosPacAuthData authData = new KerberosPacAuthData(pacData, keys);

            Pac result = authData.getPac();
            assertNotNull(result);
        }
    }

    private byte[] createMinimalPacData() throws PACDecodingException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            // Write minimal PAC header
            dos.writeInt(Integer.reverseBytes(3)); // 3 buffers
            dos.writeInt(Integer.reverseBytes(PacConstants.PAC_VERSION));

            // Write buffer entries
            dos.writeInt(Integer.reverseBytes(PacConstants.LOGON_INFO));
            dos.writeInt(Integer.reverseBytes(10));
            dos.writeLong(Long.reverseBytes(100));

            dos.writeInt(Integer.reverseBytes(PacConstants.SERVER_CHECKSUM));
            dos.writeInt(Integer.reverseBytes(16));
            dos.writeLong(Long.reverseBytes(200));

            dos.writeInt(Integer.reverseBytes(PacConstants.PRIVSVR_CHECKSUM));
            dos.writeInt(Integer.reverseBytes(16));
            dos.writeLong(Long.reverseBytes(300));

            // Add some padding
            for (int i = 0; i < 300; i++) {
                dos.writeByte(0);
            }

            return baos.toByteArray();
        } catch (IOException e) {
            throw new PACDecodingException("Failed to create test data", e);
        }
    }
}
