package jcifs.smb;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.stream.Stream;
import java.util.function.Supplier;

import javax.security.auth.Subject;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Credentials;

/**
 * Tests for SmbRenewableCredentials interface.
 *
 * Since this file is an interface with a single method, we provide small
 * helper implementations to exercise expected interaction patterns and edge cases.
 */
@ExtendWith(MockitoExtension.class)
public class SmbRenewableCredentialsTest {

    // Simple base class to satisfy the extended CredentialsInternal contract
    static abstract class BaseCreds implements SmbRenewableCredentials {
        @Override
        public CredentialsInternal clone() {
            // For testing purposes, return this instance (allowed by return type)
            return this;
        }

        @Override
        public SSPContext createContext(
                CIFSContext tc,
                String targetDomain,
                String host,
                byte[] initialToken,
                boolean doSigning) throws SmbException {
            // Not used within these tests
            throw new SmbException("not used in tests");
        }

        @Override
        public Subject getSubject() {
            return null; // not relevant for renew() behavior
        }

        @Override
        public void refresh() throws CIFSException {
            // no-op for tests
        }

        @Override
        public boolean isGuest() {
            return false; // not guest for test purposes
        }

        @Override
        public boolean isAnonymous() {
            return false; // not anonymous for test purposes
        }

        @Override
        public String getUserDomain() {
            return "TESTDOMAIN"; // test domain for test purposes
        }

        @Override
        public <T extends Credentials> T unwrap(Class<T> type) {
            if (type.isInstance(this)) {
                return type.cast(this);
            }
            throw new ClassCastException("Cannot unwrap to " + type.getName());
        }
    }

    static class SelfRenewingCreds extends BaseCreds {
        @Override
        public CredentialsInternal renew() {
            // Returns itself as the renewed credentials
            return this;
        }
    }

    static class NewRenewingCreds extends BaseCreds {
        @Override
        public CredentialsInternal renew() {
            // Returns a distinct, new credentials instance
            return new NewRenewingCreds();
        }
    }

    static class NullRenewingCreds extends BaseCreds {
        @Override
        public CredentialsInternal renew() {
            // Returns null to represent an implementation that could not renew
            return null;
        }
    }

    // Provide different implementation behaviors to a parameterized test
    static Stream<Arguments> implementations() {
        return Stream.of(
            Arguments.of("returns self", (Supplier<SmbRenewableCredentials>) SelfRenewingCreds::new, true, false),
            Arguments.of("returns new", (Supplier<SmbRenewableCredentials>) NewRenewingCreds::new, false, true),
            Arguments.of("returns null", (Supplier<SmbRenewableCredentials>) NullRenewingCreds::new, false, false)
        );
    }

    @ParameterizedTest(name = "renew() {0}")
    @MethodSource("implementations")
    @DisplayName("renew() behaviors across implementations")
    void renewBehaviorsAcrossImplementations(String label,
                                             Supplier<SmbRenewableCredentials> supplier,
                                             boolean expectSame,
                                             boolean expectNew) {
        // Arrange: create an implementation instance
        SmbRenewableCredentials impl = supplier.get();

        // Act: call renew
        CredentialsInternal renewed = impl.renew();

        // Assert: verify behavior based on scenario
        if ( expectSame ) {
            assertSame(impl, renewed, "renew() should return the same instance");
        } else if ( expectNew ) {
            assertNotNull(renewed, "renew() should return a new non-null instance");
            assertNotSame(impl, renewed, "renew() should return a different instance");
            assertTrue(renewed instanceof SmbRenewableCredentials,
                "renewed credentials should still be SmbRenewableCredentials");
        } else {
            assertNull(renewed, "renew() may return null for failed renewal");
        }
    }

    @Test
    @DisplayName("Mockito: verify renew() interaction and return value")
    void mockitoInteraction(@Mock CredentialsInternal returned,
                            @Mock SmbRenewableCredentials renewable) {
        // Arrange: stub renew() to return a mocked CredentialsInternal
        when(renewable.renew()).thenReturn(returned);

        // Act: invoke renew()
        CredentialsInternal result = renewable.renew();

        // Assert: verify interaction and returned value
        verify(renewable, times(1)).renew();
        assertSame(returned, result, "renew() should return the stubbed value");

        // Negative interaction check: no further interactions with the mock
        verifyNoMoreInteractions(renewable);
    }

    @Test
    @DisplayName("Edge: calling renew() on a null reference throws NPE")
    void renewOnNullReferenceThrowsNPE() {
        // Arrange: null reference to the interface
        SmbRenewableCredentials creds = null;

        // Act + Assert: invoking renew() on null triggers NullPointerException
        assertThrows(NullPointerException.class, () -> {
            // Intentional NPE through dereference of a null interface reference
            creds.renew();
        });
    }

    @Test
    @DisplayName("Type contract: implementation is also CredentialsInternal")
    void typeContract() {
        // Arrange: any implementation of SmbRenewableCredentials must satisfy CredentialsInternal
        SmbRenewableCredentials impl = new SelfRenewingCreds();

        // Assert: the extended interface relationship holds
        assertTrue(impl instanceof CredentialsInternal, "Should be usable as CredentialsInternal");

        // Cast and check we can call clone() from CredentialsInternal contract
        CredentialsInternal ci = (CredentialsInternal) impl;
        CredentialsInternal cloned = ci.clone();
        assertNotNull(cloned, "clone() should return a non-null CredentialsInternal");
    }
}

