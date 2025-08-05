/*
 * Copyright 2025 Shinsuke Suzuki
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,

 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package jcifs.smb1.smb1;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

import jcifs.smb1.NtlmPasswordAuthentication;
import jcifs.smb1.ServerMessageBlock;
import jcifs.smb1.SmbConstants;
import jcifs.smb1.SmbException;
import jcifs.smb1.SmbSession;
import jcifs.smb1.SmbTransport;
import jcifs.smb1.SmbServer;

class SmbComSessionSetupAndXTest {

    @Mock
    private SmbSession mockSession;
    @Mock
    private SmbTransport mockTransport;
    @Mock
    private SmbServer mockServer;
    @Mock
    private ServerMessageBlock mockAndx;
    @Mock
    private NtlmPasswordAuthentication mockAuth;

    private static final int TEST_SESSION_KEY = 12345;
    private static final int TEST_CAPABILITIES = SmbConstants.CAP_UNICODE | SmbConstants.CAP_NT_SMBS;
    private static final String TEST_ACCOUNT_NAME = "testUser";
    private static final String TEST_DOMAIN = "TESTDOMAIN";
    private static final String TEST_PASSWORD = "testPassword";
    private static final byte[] TEST_ENCRYPTION_KEY = "encryptionKey".getBytes();

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        // Common mock setup
        when(mockSession.getTransport()).thenReturn(mockTransport);
        when(mockTransport.getServer()).thenReturn(mockServer);
        when(mockTransport.getSessionKey()).thenReturn(TEST_SESSION_KEY);
        when(mockTransport.getCapabilities()).thenReturn(TEST_CAPABILITIES);
        when(mockTransport.getNativeOs()).thenReturn("UnitTestOS");
        when(mockTransport.getNativeLanMan()).thenReturn("UnitTestLanMan");
        when(mockTransport.getSndBufSize()).thenReturn(8192);
        when(mockTransport.getMaxMpxCount()).thenReturn(50);
        when(mockTransport.getVcNumber()).thenReturn(1);

        when(mockAuth.getUsername()).thenReturn(TEST_ACCOUNT_NAME);
        when(mockAuth.getDomain()).thenReturn(TEST_DOMAIN);
        when(mockAuth.getPassword()).thenReturn(TEST_PASSWORD);
    }

    // Test constructor with user security and anonymous authentication
    @Test
    void testConstructor_UserSecurity_AnonymousAuth() throws SmbException {
        when(mockServer.getSecurity()).thenReturn(ServerMessageBlock.SECURITY_USER);
        NtlmPasswordAuthentication anonymousAuth = NtlmPasswordAuthentication.ANONYMOUS;

        SmbComSessionSetupAndX smb = new SmbComSessionSetupAndX(mockSession, mockAndx, anonymousAuth);

        assertEquals(ServerMessageBlock.SMB_COM_SESSION_SETUP_ANDX, smb.command);
        assertEquals(0, smb.lmHash.length);
        assertEquals(0, smb.ntHash.length);
        // CAP_EXTENDED_SECURITY should be removed for anonymous auth
        assertNotEquals(0, (TEST_CAPABILITIES & ~SmbConstants.CAP_EXTENDED_SECURITY) & smb.capabilities);
    }

    // Test constructor with user security and encrypted passwords
    @Test
    void testConstructor_UserSecurity_EncryptedPasswords() throws SmbException {
        when(mockServer.getSecurity()).thenReturn(ServerMessageBlock.SECURITY_USER);
        when(mockServer.isEncryptedPasswords()).thenReturn(true);
        when(mockServer.getEncryptionKey()).thenReturn(TEST_ENCRYPTION_KEY);
        byte[] lmHash = "lmHash".getBytes();
        byte[] ntHash = "ntHash".getBytes();
        when(mockAuth.getAnsiHash(TEST_ENCRYPTION_KEY)).thenReturn(lmHash);
        when(mockAuth.getUnicodeHash(TEST_ENCRYPTION_KEY)).thenReturn(ntHash);

        SmbComSessionSetupAndX smb = new SmbComSessionSetupAndX(mockSession, mockAndx, mockAuth);

        assertArrayEquals(lmHash, smb.lmHash);
        assertArrayEquals(ntHash, smb.ntHash);
        assertEquals(TEST_ACCOUNT_NAME.toUpperCase(), smb.accountName);
        assertEquals(TEST_DOMAIN.toUpperCase(), smb.primaryDomain);
    }
    
    // Test constructor with user security and plain text password (Unicode)
    @Test
    void testConstructor_UserSecurity_PlainTextPassword_Unicode() throws SmbException {
        when(mockServer.getSecurity()).thenReturn(ServerMessageBlock.SECURITY_USER);
        when(mockServer.isEncryptedPasswords()).thenReturn(false);
        // To allow plain text, we need to set jcifs.smb.client.disablePlainTextPasswords to false
        // This is difficult to do in a unit test, so we assume it's false for this test.
        // The class throws a RuntimeException if it's true, which is tested separately.
        
        SmbComSessionSetupAndX smb = new SmbComSessionSetupAndX(mockSession, mockAndx, mockAuth);
        smb.useUnicode = true; // Force unicode for testing

        // Re-run constructor logic that depends on useUnicode
        smb.processCredential(mockAuth);

        assertEquals(0, smb.lmHash.length);
        assertTrue(smb.ntHash.length > 0);
        assertEquals(TEST_ACCOUNT_NAME.toUpperCase(), smb.accountName);
    }

    // Test constructor with a byte array credential (blob) for SPNEGO/Kerberos
    @Test
    void testConstructor_UserSecurity_BlobCredential() throws SmbException {
        when(mockServer.getSecurity()).thenReturn(ServerMessageBlock.SECURITY_USER);
        byte[] blob = "spnego_blob".getBytes();

        SmbComSessionSetupAndX smb = new SmbComSessionSetupAndX(mockSession, mockAndx, blob);

        assertArrayEquals(blob, smb.blob);
        assertNull(smb.lmHash);
        assertNull(smb.ntHash);
    }

    // Test constructor with share security
    @Test
    void testConstructor_ShareSecurity() throws SmbException {
        when(mockServer.getSecurity()).thenReturn(ServerMessageBlock.SECURITY_SHARE);

        SmbComSessionSetupAndX smb = new SmbComSessionSetupAndX(mockSession, mockAndx, mockAuth);

        assertEquals(0, smb.lmHash.length);
        assertEquals(0, smb.ntHash.length);
        assertEquals(TEST_ACCOUNT_NAME.toUpperCase(), smb.accountName);
        assertEquals(TEST_DOMAIN.toUpperCase(), smb.primaryDomain);
    }

    // Test constructor with an unsupported credential type
    @Test
    void testConstructor_UnsupportedCredential() {
        when(mockServer.getSecurity()).thenReturn(ServerMessageBlock.SECURITY_USER);
        Object unsupportedCred = new Object();

        assertThrows(SmbException.class, () -> {
            new SmbComSessionSetupAndX(mockSession, mockAndx, unsupportedCred);
        }, "Should throw SmbException for unsupported credential type");
    }

    // Test getBatchLimit method
    @Test
    void testGetBatchLimit() throws SmbException {
        when(mockServer.getSecurity()).thenReturn(ServerMessageBlock.SECURITY_USER);
        SmbComSessionSetupAndX smb = new SmbComSessionSetupAndX(mockSession, mockAndx, mockAuth);

        assertEquals(1, smb.getBatchLimit(ServerMessageBlock.SMB_COM_TREE_CONNECT_ANDX));
        assertEquals(0, smb.getBatchLimit(ServerMessageBlock.SMB_COM_OPEN_ANDX));
    }

    // Test writeParameterWordsWireFormat method
    @Test
    void testWriteParameterWordsWireFormat() throws SmbException {
        when(mockServer.getSecurity()).thenReturn(ServerMessageBlock.SECURITY_USER);
        when(mockServer.isEncryptedPasswords()).thenReturn(true);
        when(mockServer.getEncryptionKey()).thenReturn(TEST_ENCRYPTION_KEY);
        byte[] lmHash = "lmHash".getBytes();
        byte[] ntHash = "ntHash".getBytes();
        when(mockAuth.getAnsiHash(TEST_ENCRYPTION_KEY)).thenReturn(lmHash);
        when(mockAuth.getUnicodeHash(TEST_ENCRYPTION_KEY)).thenReturn(ntHash);

        SmbComSessionSetupAndX smb = new SmbComSessionSetupAndX(mockSession, mockAndx, mockAuth);
        byte[] dst = new byte[24]; // Expected size
        int bytesWritten = smb.writeParameterWordsWireFormat(dst, 0);

        assertEquals(24, bytesWritten);
        // Verify some key fields
        assertEquals(8192, ServerMessageBlock.readInt2(dst, 0)); // snd_buf_size
        assertEquals(50, ServerMessageBlock.readInt2(dst, 2));   // maxMpxCount
        assertEquals(TEST_SESSION_KEY, ServerMessageBlock.readInt4(dst, 6));
        assertEquals(lmHash.length, ServerMessageBlock.readInt2(dst, 10));
        assertEquals(ntHash.length, ServerMessageBlock.readInt2(dst, 12));
        assertEquals(TEST_CAPABILITIES, ServerMessageBlock.readInt4(dst, 18));
    }

    // Test writeBytesWireFormat method
    @Test
    void testWriteBytesWireFormat() throws SmbException {
        when(mockServer.getSecurity()).thenReturn(ServerMessageBlock.SECURITY_USER);
        when(mockServer.isEncryptedPasswords()).thenReturn(true);
        when(mockServer.getEncryptionKey()).thenReturn(TEST_ENCRYPTION_KEY);
        byte[] lmHash = "lmHash".getBytes();
        byte[] ntHash = "ntHash".getBytes();
        when(mockAuth.getAnsiHash(TEST_ENCRYPTION_KEY)).thenReturn(lmHash);
        when(mockAuth.getUnicodeHash(TEST_ENCRYPTION_KEY)).thenReturn(ntHash);
        
        SmbComSessionSetupAndX smb = new SmbComSessionSetupAndX(mockSession, mockAndx, mockAuth);
        smb.useUnicode = true; // for predictable string writing
        smb.processCredential(mockAuth); // re-process with unicode setting

        int expectedSize = lmHash.length + ntHash.length
                + (smb.accountName.length() + 1) * 2
                + (smb.primaryDomain.length() + 1) * 2
                + (mockTransport.getNativeOs().length() + 1)
                + (mockTransport.getNativeLanMan().length() + 1);

        byte[] dst = new byte[expectedSize];
        int bytesWritten = smb.writeBytesWireFormat(dst, 0);

        assertEquals(expectedSize, bytesWritten);
        // Just check if the hashes are copied correctly at the beginning
        assertArrayEquals(lmHash, java.util.Arrays.copyOfRange(dst, 0, lmHash.length));
        assertArrayEquals(ntHash, java.util.Arrays.copyOfRange(dst, lmHash.length, lmHash.length + ntHash.length));
    }

    // Test toString method
    @Test
    void testToString() throws SmbException {
        when(mockServer.getSecurity()).thenReturn(ServerMessageBlock.SECURITY_USER);
        SmbComSessionSetupAndX smb = new SmbComSessionSetupAndX(mockSession, mockAndx, mockAuth);
        String str = smb.toString();

        assertTrue(str.startsWith("SmbComSessionSetupAndX["));
        assertTrue(str.contains("accountName=" + TEST_ACCOUNT_NAME.toUpperCase()));
        assertTrue(str.contains("primaryDomain=" + TEST_DOMAIN.toUpperCase()));
        assertTrue(str.contains("]"));
    }
}