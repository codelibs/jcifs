package jcifs.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.internal.smb1.AndXServerMessageBlock;
import jcifs.internal.smb1.com.ServerData;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.smb1.com.SmbComNegotiateResponse;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.NtlmPasswordAuthenticator;
import jcifs.smb.SmbException;

/**
 * Unit tests exercising {@link SmbComSessionSetupAndX}.  The class under test
 * contains several protected helper methods and a complex constructor
 * that branches on credential type.  These tests use reflection to call
 * protected methods and Mockito to stub collaborators.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class SmbComSessionSetupAndXTest {

    @Mock
    private CIFSContext mockContext;
    @Mock
    private SmbComNegotiateResponse mockNegotiate;
    @Mock
    private ServerMessageBlock mockAndX;
    @Mock
    private Configuration mockConfig;

    private static byte[] blobCred() {
        return "blobdata".getBytes(StandardCharsets.UTF_8);
    }

    @BeforeEach
    void setup() {
        when(mockContext.getConfig()).thenReturn(mockConfig);
        when(mockNegotiate.getServerData()).thenReturn(new ServerDataStub());
    }

    private void setupNegotiateStubs() {
        when(mockNegotiate.getNegotiatedCapabilities()).thenReturn(0x00123456);
        when(mockNegotiate.getNegotiatedSendBufferSize()).thenReturn(65535);
        when(mockNegotiate.getNegotiatedMpxCount()).thenReturn(65535);
        when(mockNegotiate.getNegotiatedSessionKey()).thenReturn(0x12345678);
    }

    /** Simple test stub of {@link ServerData} */
    private static class ServerDataStub extends ServerData {
        public ServerDataStub() {
            this.security = SmbConstants.SECURITY_USER;
            this.encryptedPasswords = false;
            this.encryptionKey = new byte[0];
        }
    }

    @Test
    void anonymousGuestCredentials() throws Exception {
        setupNegotiateStubs();
        
        NtlmPasswordAuthenticator auth = mock(NtlmPasswordAuthenticator.class);
        when(auth.isAnonymous()).thenReturn(true);
        when(auth.isGuest()).thenReturn(true);
        when(auth.getUsername()).thenReturn("guest");
        when(auth.getUserDomain()).thenReturn("dom");
        
        // Construct
        SmbComSessionSetupAndX obj = new SmbComSessionSetupAndX(
                mockContext, mockNegotiate, mockAndX, auth);
        String accountName = (String) getField(obj, "accountName");
        String primaryDomain = (String) getField(obj, "primaryDomain");
        
        // The actual implementation keeps lowercase for guest when Unicode is not enabled
        assertEquals("guest", accountName);
        assertEquals("DOM", primaryDomain);
        
        byte[] lm = (byte[]) getField(obj, "lmHash");
        byte[] nt = (byte[]) getField(obj, "ntHash");
        assertArrayEquals(new byte[0], lm);
        assertArrayEquals(new byte[0], nt);
    }

    @Test
    void unsupportedCredentialType() {
        assertThrows(SmbException.class, () ->
                new SmbComSessionSetupAndX(mockContext, mockNegotiate, mockAndX, "foo"));
    }

    @Test
    void byteArrayBlob() throws Exception {
        SmbComSessionSetupAndX obj = new SmbComSessionSetupAndX(
                mockContext, mockNegotiate, mockAndX, blobCred());
        assertArrayEquals(blobCred(), (byte[]) getField(obj, "blob"));
    }

    @Test
    void writeParameterWordsWithBlob() throws Exception {
        setupNegotiateStubs();
        when(mockConfig.getVcNumber()).thenReturn(0);
        when(mockConfig.getNativeOs()).thenReturn("Test OS");
        when(mockConfig.getNativeLanman()).thenReturn("Test LAN");
        
        byte[] blob = blobCred();
        SmbComSessionSetupAndX obj = new SmbComSessionSetupAndX(
                mockContext, mockNegotiate, mockAndX, blob);
        byte[] buf = new byte[256];
        int len = invokeProtectedInt(obj, "writeParameterWordsWireFormat", buf, 0);
        
        // Expected size: 2 (sendBuffer) + 2 (mpxCount) + 2 (vcNumber) + 4 (sessionKey) + 2 (blob length) + 4 (reserved) + 4 (capabilities)
        int expected = 2 + 2 + 2 + 4 + 2 + 4 + 4;
        assertEquals(expected, len);
        
        int off = 0;
        assertEquals(65535, SMBUtil.readInt2(buf, off)); off += 2;
        assertEquals(65535, SMBUtil.readInt2(buf, off)); off += 2;
        assertEquals(0, SMBUtil.readInt2(buf, off)); off += 2;
        assertEquals(0x12345678, SMBUtil.readInt4(buf, off)); off += 4;
        assertEquals(blob.length, SMBUtil.readInt2(buf, off));
    }

    // --- reflection helpers --------------------------------------------
    private static Object getField(Object target, String name) {
        try {
            var f = target.getClass().getDeclaredField(name);
            f.setAccessible(true);
            return f.get(target);
        } catch (Exception e) {
            fail("access field " + name, e);
            return null;
        }
    }
    
    private static int invokeProtectedInt(Object target, String name,
            Object... params) {
        try {
            var cls = target.getClass();
            // Build proper parameter types array, handling primitive types
            Class<?>[] paramTypes = new Class<?>[params.length];
            for (int i = 0; i < params.length; i++) {
                if (params[i] instanceof byte[]) {
                    paramTypes[i] = byte[].class;
                } else if (params[i] instanceof Integer) {
                    paramTypes[i] = int.class;  // Use primitive int.class instead of Integer.class
                } else {
                    paramTypes[i] = params[i].getClass();
                }
            }
            var m = cls.getDeclaredMethod(name, paramTypes);
            m.setAccessible(true);
            return (int) m.invoke(target, params);
        } catch (Exception e) {
            fail("invoke " + name, e);
            return -1;
        }
    }
}

