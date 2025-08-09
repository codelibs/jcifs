package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.net.InetAddress;
import jcifs.smb1.smb1.NtlmPasswordAuthentication;
import jcifs.smb1.smb1.ServerMessageBlock;
import jcifs.smb1.smb1.SmbComOpen;
import jcifs.smb1.smb1.SmbTransport;
import jcifs.smb1.smb1.SmbSession;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Very small test suite that exercises the most important state‑changing
 * behaviour of {@link SmbSession}.  The tests use Mockito to stub the
 * heavy network interactions through {@link SmbTransport}.
 */
@ExtendWith(MockitoExtension.class)
public class SmbSessionTest {

    @Mock UniAddress addr;
    @Mock InetAddress inet;
    @Mock NtlmPasswordAuthentication auth;
    @Mock SmbTransport transport;

    // static helper that returns the mocked transport.  The real class
    // performs several other operations, but for the purpose of the test
    // we intercept the factory call.
    private MockedStatic<SmbTransport> smbtStatic;

    @BeforeEach
    void setUp() throws Exception {
        smbtStatic = mockStatic(SmbTransport.class);
        smbtStatic.when(() -> SmbTransport.getSmbTransport(addr, 445, inet, 0, null))
                .thenReturn(transport);
        smbtStatic.when(() -> SmbTransport.getSmbTransport(addr, 445)).thenReturn(transport);
    }

    @Test
    void transportLazyInitialisation() {
        SmbSession session = new SmbSession(addr, 445, inet, 0, auth);
        // transport should still be null until first use
        assertNull(session.transport(), "transport not created yet");
        SmbTransport tr = session.transport();
        assertNotNull(tr, "transport should now exist");
        // subsequent calls return the same instance
        assertSame(tr, session.transport());
    }

    @Test
    void sendResetsResponseAndForwards() throws Exception {
        SmbSession session = new SmbSession(addr, 445, inet, 0, auth);
        // prepare a dummy request/response using a real SMB block type
        ServerMessageBlock req = new SmbComOpen();
        ServerMessageBlock resp = new SmbComOpen();
        resp.received = true;

        session.transport(); // initialise transport
        doNothing().when(transport).send(eq(req), eq(resp));

        session.send(req, resp);
        // Response state reset
        assertFalse(resp.received, "Response flag should be reset");
        // transport.send called with same objects
        verify(transport, times(1)).send(eq(req), eq(resp));
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
