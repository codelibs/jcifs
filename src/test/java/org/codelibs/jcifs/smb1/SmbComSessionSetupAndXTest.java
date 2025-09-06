package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.SmbConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class SmbComSessionSetupAndXTest {

    @Mock
    private SmbSession mockSession;
    @Mock
    private SmbTransport mockTransport;
    @Mock
    private ServerMessageBlock mockAndx;
    @Mock
    private NtlmPasswordAuthentication mockAuth;

    private SmbComSessionSetupAndX setupAndX;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);

        // Create a real ServerData instance as it's not mockable (inner class)
        SmbTransport.ServerData serverData = mockTransport.new ServerData();
        serverData.security = ServerMessageBlock.SECURITY_USER;
        serverData.encryptedPasswords = true;
        serverData.encryptionKey = new byte[8];

        // Configure mock transport
        mockTransport.server = serverData;
        mockTransport.sessionKey = 0x12345678;
        mockTransport.capabilities = SmbConstants.CAP_UNICODE | SmbConstants.CAP_NT_SMBS;
        mockTransport.snd_buf_size = 16644;
        mockTransport.maxMpxCount = 50;

        // Configure mock session
        mockSession.transport = mockTransport;

        // Configure authentication - set fields directly since NtlmPasswordAuthentication is final
        mockAuth.username = "testuser";
        mockAuth.domain = "TESTDOMAIN";
        mockAuth.password = "testpass";

        when(mockAuth.getAnsiHash(any(byte[].class))).thenReturn(new byte[24]);
        when(mockAuth.getUnicodeHash(any(byte[].class))).thenReturn(new byte[24]);
        when(mockAuth.getName()).thenReturn("testuser");
        when(mockAuth.getDomain()).thenReturn("TESTDOMAIN");

        setupAndX = new SmbComSessionSetupAndX(mockSession, mockAndx, mockAuth);
    }

    @Test
    void testConstructor() {
        assertNotNull(setupAndX);
        assertEquals(ServerMessageBlock.SMB_COM_SESSION_SETUP_ANDX, setupAndX.command);
        assertEquals(mockSession, setupAndX.session);
        assertEquals(mockAuth, setupAndX.cred);
    }

    @Test
    void testConstructorWithAnonymousAuth() throws Exception {
        // Test with anonymous authentication
        SmbComSessionSetupAndX anonSetup = new SmbComSessionSetupAndX(mockSession, mockAndx, NtlmPasswordAuthentication.ANONYMOUS);
        assertNotNull(anonSetup);
        assertEquals(ServerMessageBlock.SMB_COM_SESSION_SETUP_ANDX, anonSetup.command);
    }

    @Test
    void testConstructorWithSecurityShare() throws Exception {
        // Test with SECURITY_SHARE mode
        mockTransport.server.security = ServerMessageBlock.SECURITY_SHARE;

        SmbComSessionSetupAndX shareSetup = new SmbComSessionSetupAndX(mockSession, mockAndx, mockAuth);
        assertNotNull(shareSetup);
        assertEquals(ServerMessageBlock.SMB_COM_SESSION_SETUP_ANDX, shareSetup.command);
    }

    @Test
    void testWriteParameterWordsWireFormat() {
        byte[] dst = new byte[1024];
        int result = setupAndX.writeParameterWordsWireFormat(dst, 0);

        // Verify that data was written (should write 22 bytes based on implementation)
        assertEquals(22, result, "writeParameterWordsWireFormat should write 22 bytes");
    }

    @Test
    void testWriteBytesWireFormat() {
        byte[] dst = new byte[1024];
        int result = setupAndX.writeBytesWireFormat(dst, 0);

        // Verify that data was written
        assertTrue(result >= 0, "writeBytesWireFormat should return non-negative value");
    }

    @Test
    void testReadParameterWordsWireFormat() {
        byte[] buffer = new byte[1024];

        int result = setupAndX.readParameterWordsWireFormat(buffer, 0);

        // The implementation always returns 0
        assertEquals(0, result, "readParameterWordsWireFormat returns 0");
    }

    @Test
    void testReadBytesWireFormat() {
        byte[] buffer = new byte[1024];

        int result = setupAndX.readBytesWireFormat(buffer, 0);

        // The implementation always returns 0
        assertEquals(0, result, "readBytesWireFormat returns 0");
    }

    @Test
    void testToString() {
        String result = setupAndX.toString();
        assertNotNull(result);
        assertTrue(result.contains("SmbComSessionSetupAndX"), "toString should contain class name");
    }
}
