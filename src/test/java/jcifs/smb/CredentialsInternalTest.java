package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import java.util.stream.Stream;

import javax.security.auth.Subject;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Credentials;

@ExtendWith(MockitoExtension.class)
class CredentialsInternalTest {

    @Mock
    CIFSContext mockContext;

    /**
     * Simple in-test implementation of CredentialsInternal to exercise the API surface.
     * It validates inputs, records calls, and delegates some behavior to collaborators
     * so we can verify interactions.
     */
    static class TestCredentials implements CredentialsInternal {
        private final String domain;
        private final boolean anonymous;
        private final boolean guest;
        private final Subject subject;
        private final boolean failOnRefresh;

        TestCredentials(String domain, boolean anonymous, boolean guest, Subject subject, boolean failOnRefresh) {
            this.domain = domain;
            this.anonymous = anonymous;
            this.guest = guest;
            this.subject = subject;
            this.failOnRefresh = failOnRefresh;
        }

        @Override
        public TestCredentials clone() {
            // Return a shallow copy with the same field values
            return new TestCredentials(this.domain, this.anonymous, this.guest, this.subject, this.failOnRefresh);
        }

        @Override
        public SSPContext createContext(CIFSContext tc, String targetDomain, String host, byte[] initialToken, boolean doSigning)
                throws SmbException {
            // Validate required argument and interact with the provided CIFSContext
            if (tc == null) {
                throw new NullPointerException("tc");
            }
            // Exercise interaction with dependency for verification purposes
            // These methods do not throw and allow interaction checks.
            tc.getConfig();
            tc.getCredentials();

            // Minimal behavior: return a mock SSPContext with lenient stubbing
            SSPContext ctx = mock(SSPContext.class);
            lenient().when(ctx.isEstablished()).thenReturn(false);
            return ctx;
        }

        @Override
        public Subject getSubject() {
            return this.subject;
        }

        @Override
        public void refresh() throws CIFSException {
            if (failOnRefresh) {
                throw new CIFSException("refresh failed");
            }
        }

        // ----- Credentials (super-interface) -----

        @Override
        public <T extends Credentials> T unwrap(Class<T> type) {
            if (type == null) {
                throw new NullPointerException("type");
            }
            if (type.isInstance(this)) {
                return type.cast(this);
            }
            return null;
        }

        @Override
        public String getUserDomain() {
            return this.domain;
        }

        @Override
        public boolean isAnonymous() {
            return this.anonymous;
        }

        @Override
        public boolean isGuest() {
            return this.guest;
        }
    }

    static Stream<boolean[]> anonGuestFlags() {
        return Stream.of(new boolean[] { false, false }, new boolean[] { true, false }, new boolean[] { false, true },
                new boolean[] { true, true });
    }

    @ParameterizedTest
    @MethodSource("anonGuestFlags")
    @DisplayName("unwrap, domain, anonymous/guest flags happy paths")
    void unwrap_and_flags_happy(boolean[] flags) {
        boolean anonymous = flags[0];
        boolean guest = flags[1];

        // Arrange
        Subject subject = new Subject();
        TestCredentials creds = new TestCredentials("DOMAIN", anonymous, guest, subject, false);

        // Act & Assert
        // unwrap to interface itself should return same instance
        CredentialsInternal unwrapped = creds.unwrap(CredentialsInternal.class);
        assertNotNull(unwrapped, "unwrap to CredentialsInternal returns instance");
        assertSame(creds, unwrapped, "unwrap returns the same object instance");

        // unwrap to unrelated type should return null (use another Credentials implementation)
        assertNull(creds.unwrap(NtlmPasswordAuthenticator.class), "unwrap to unrelated type returns null");

        // domain and flags are surfaced as given
        assertEquals("DOMAIN", creds.getUserDomain());
        assertEquals(anonymous, creds.isAnonymous());
        assertEquals(guest, creds.isGuest());
    }

    @Test
    @DisplayName("unwrap throws on null type")
    void unwrap_null_type_throws() {
        TestCredentials creds = new TestCredentials("DOM", false, false, new Subject(), false);
        // Act & Assert
        NullPointerException npe = assertThrows(NullPointerException.class, () -> creds.unwrap(null));
        assertEquals("type", npe.getMessage());
    }

    @Test
    @DisplayName("clone returns a distinct copy with same properties")
    void clone_returns_copy() {
        // Arrange
        Subject subject = new Subject();
        TestCredentials creds = new TestCredentials("A", true, false, subject, false);

        // Act
        TestCredentials copy = creds.clone();

        // Assert
        assertNotSame(creds, copy, "clone must return a new instance");
        assertEquals(creds.getUserDomain(), copy.getUserDomain());
        assertEquals(creds.isAnonymous(), copy.isAnonymous());
        assertEquals(creds.isGuest(), copy.isGuest());
        assertSame(subject, copy.getSubject(), "subject is the same reference in clone");
    }

    @Test
    @DisplayName("createContext returns SSPContext and interacts with CIFSContext")
    void createContext_happy_interacts_and_returns_context() throws Exception {
        // Arrange
        TestCredentials creds = new TestCredentials("D", false, false, new Subject(), false);

        // Act
        SSPContext ctx = creds.createContext(mockContext, "TARGET", "host", new byte[0], true);

        // Assert
        assertNotNull(ctx, "createContext returns an SSPContext");
        assertFalse(ctx.isEstablished(), "stub context initially not established");

        // Verify interactions with dependency are meaningful and ordered
        InOrder order = inOrder(mockContext);
        order.verify(mockContext, times(1)).getConfig();
        order.verify(mockContext, times(1)).getCredentials();
        verifyNoMoreInteractions(mockContext);
    }

    @Test
    @DisplayName("createContext throws on null CIFSContext")
    void createContext_null_context_throws() {
        // Arrange
        TestCredentials creds = new TestCredentials("D", false, false, new Subject(), false);

        // Act & Assert
        NullPointerException npe = assertThrows(NullPointerException.class, () -> creds.createContext(null, "T", "h", new byte[0], false));
        assertEquals("tc", npe.getMessage());
    }

    @Test
    @DisplayName("createContext accepts null/empty optional parameters")
    void createContext_edge_parameters_ok() throws Exception {
        TestCredentials creds = new TestCredentials("D", false, false, new Subject(), false);
        // Intentionally pass null/empty values for optional parameters; expect no exception
        SSPContext ctx1 = creds.createContext(mockContext, null, "", null, false);
        assertNotNull(ctx1);
    }

    @Nested
    @DisplayName("getSubject edge cases")
    class SubjectTests {
        @Test
        @DisplayName("returns provided subject")
        void subject_non_null() {
            Subject s = new Subject();
            TestCredentials creds = new TestCredentials("X", false, false, s, false);
            assertSame(s, creds.getSubject());
        }

        @Test
        @DisplayName("allows null subject")
        void subject_null() {
            TestCredentials creds = new TestCredentials("X", false, false, null, false);
            assertNull(creds.getSubject());
        }
    }

    @Test
    @DisplayName("refresh succeeds when not configured to fail")
    void refresh_success() throws Exception {
        TestCredentials creds = new TestCredentials("Z", false, false, new Subject(), false);
        // Should not throw
        assertDoesNotThrow(creds::refresh);
    }

    @Test
    @DisplayName("refresh throws CIFSException when configured to fail")
    void refresh_failure_throws_cifs() {
        TestCredentials creds = new TestCredentials("Z", false, false, new Subject(), true);
        CIFSException ex = assertThrows(CIFSException.class, creds::refresh);
        assertTrue(ex.getMessage().contains("refresh failed"));
    }

    @ParameterizedTest
    @MethodSource("domains")
    @DisplayName("getUserDomain handles null and empty")
    void getUserDomain_edges(String domain) {
        TestCredentials creds = new TestCredentials(domain, false, false, new Subject(), false);
        assertEquals(domain, creds.getUserDomain());
    }

    static Stream<String> domains() {
        return Stream.of(null, "", "SALES");
    }
}
