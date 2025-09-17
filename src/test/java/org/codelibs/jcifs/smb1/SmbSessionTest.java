package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;

import java.net.InetAddress;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Very small test suite that exercises the most important state-changing
 * behaviour of {@link SmbSession}. The tests use Mockito to stub the
 * heavy network interactions through {@link SmbTransport}.
 */
@ExtendWith(MockitoExtension.class)
public class SmbSessionTest {

    @Mock
    UniAddress addr;
    @Mock
    InetAddress inet;
    NtlmPasswordAuthentication auth;
    @Mock
    SmbTransport transport;

    // static helper that returns the mocked transport. The real class
    // performs several other operations, but for the purpose of the test
    // we intercept the factory call.
    private MockedStatic<SmbTransport> smbtStatic;

    @BeforeEach
    void setUp() throws Exception {
        // Create a real NtlmPasswordAuthentication instance
        auth = new NtlmPasswordAuthentication("TESTDOMAIN", "testuser", "testpass");

        // Initialize ServerData to avoid NullPointerException
        SmbTransport.ServerData serverData = transport.new ServerData();
        serverData.security = 0; // Set to 0 or appropriate value for SECURITY_SHARE
        serverData.encryptionKey = new byte[8]; // Initialize with empty encryption key

        // Configure the mock transport with the server data
        transport.server = serverData;

        smbtStatic = mockStatic(SmbTransport.class);
        smbtStatic.when(() -> SmbTransport.getSmbTransport(addr, 445, inet, 0, null)).thenReturn(transport);
        smbtStatic.when(() -> SmbTransport.getSmbTransport(addr, 445)).thenReturn(transport);
    }

    @AfterEach
    void tearDown() {
        if (smbtStatic != null) {
            smbtStatic.close();
        }
    }

    @Test
    void transportLazyInitialisation() {
        SmbSession session = new SmbSession(addr, 445, inet, 0, auth);
        // transport should still be null until first use
        assertNull(session.transport, "transport not created yet");
        SmbTransport tr = session.transport();
        assertNotNull(tr, "transport should now exist");
        // subsequent calls return the same instance
        assertSame(tr, session.transport());
    }

    @Test
    void sendResetsResponseAndForwards() throws Exception {
        SmbSession session = new SmbSession(addr, 445, inet, 0, auth);
        // prepare a dummy request/response using a real SMB block type
        ServerMessageBlock req = new SmbComOpenAndX("test.txt", 0, 0, null);
        ServerMessageBlock resp = new SmbComOpenAndX("test.txt", 0, 0, null);
        resp.received = true;

        session.transport(); // initialise transport

        // Mock the sessionSetup behavior to avoid actual network calls
        // The sessionSetup method would normally send authentication messages
        // Only mark the sessionSetup response as received, not the actual request/response
        doAnswer(invocation -> {
            ServerMessageBlock request = invocation.getArgument(0);
            ServerMessageBlock response = invocation.getArgument(1);
            // Only mark session setup responses as received, not our test request
            if (response != null && request.getClass().getName().contains("SessionSetup")) {
                response.received = true;
            }
            return null;
        }).when(transport).send(any(ServerMessageBlock.class), any(ServerMessageBlock.class));

        session.send(req, resp);
        // Response state should be reset
        assertFalse(resp.received, "Response flag should be reset");
        // transport.send should be called at least once (for sessionSetup and the actual request)
        verify(transport, atLeastOnce()).send(any(ServerMessageBlock.class), any(ServerMessageBlock.class));
    }

    @Test
    void matchesBehavior() {
        // Two distinct auth instances
        NtlmPasswordAuthentication a1 = new NtlmPasswordAuthentication("DOM", "user", "pwd");
        NtlmPasswordAuthentication a2 = new NtlmPasswordAuthentication("DOM", "user", "pwd");
        SmbSession s1 = new SmbSession(addr, 445, inet, 0, a1);
        SmbSession s2 = new SmbSession(addr, 445, inet, 0, a2);
        // same auth instance => matches
        assertTrue(s1.matches(a1));
        // different instance but equal content => matches
        assertTrue(s1.matches(a2));
        // not equal => no match
        NtlmPasswordAuthentication other = new NtlmPasswordAuthentication("OTHER", "u", "p");
        assertFalse(s1.matches(other));
    }

    @Test
    void toStringContainsKeyFields() {
        SmbSession session = new SmbSession(addr, 445, inet, 0, auth);
        String s = session.toString();
        assertTrue(s.contains("accountName="), "toString should contain accountName");
        assertTrue(s.contains("primaryDomain="), "toString should contain primaryDomain");
        assertTrue(s.contains("uid="), "toString should contain uid");
    }
}