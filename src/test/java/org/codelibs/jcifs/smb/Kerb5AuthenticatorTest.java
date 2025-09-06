package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.security.Principal;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.codelibs.jcifs.smb.spnego.NegTokenInit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class Kerb5AuthenticatorTest {

    @Mock
    CIFSContext tc;

    @Mock
    Configuration config;

    private static byte[] spnegoInitWithMechs(ASN1ObjectIdentifier... mechs) {
        // Build a minimal SPNEGO NegTokenInit containing the provided mechanisms
        NegTokenInit tok = new NegTokenInit(mechs, 0, null, null);
        return tok.toByteArray();
    }

    @Test
    @DisplayName("createContext: rejects NetBIOS/short host names")
    void createContext_rejectsShortNetbiosHost() {
        Kerb5Authenticator auth = new Kerb5Authenticator((Subject) null);

        // Using an uppercase short name (no dot) must throw an unsupported operation
        SmbUnsupportedOperationException ex =
                assertThrows(SmbUnsupportedOperationException.class, () -> auth.createContext(tc, null, "SERVER", new byte[0], false));
        assertTrue(ex.getMessage().contains("Cannot use netbios/short names"));
    }

    @Test
    @DisplayName("createContext: no Kerberos in initial token and no fallback -> throws")
    void createContext_noKerberosNoFallback_throws() throws CIFSException {
        Kerb5Authenticator auth = new Kerb5Authenticator((Subject) null);

        // Build a token with an arbitrary non-kerberos mechanism OID
        ASN1ObjectIdentifier unsupported = new ASN1ObjectIdentifier("1.2.3.4.5");
        byte[] init = spnegoInitWithMechs(unsupported);

        // Host is a FQDN to pass the short-name check
        SmbUnsupportedOperationException ex =
                assertThrows(SmbUnsupportedOperationException.class, () -> auth.createContext(tc, null, "server.example.com", init, false));
        assertTrue(ex.getMessage().contains("Server does not support kerberos authentication"));
        // No fallback attempted; config should not be queried in this path
        verify(tc, never()).getConfig();
        verifyNoInteractions(config);
    }

    @Test
    @DisplayName("createContext: Kerberos present but forceFallback triggers NTLM path")
    void createContext_forceFallback_triggersNtlmAndFailsOnNonNtlmToken() throws CIFSException {
        when(tc.getConfig()).thenReturn(config);
        when(config.isAllowNTLMFallback()).thenReturn(true);
        when(config.isUseRawNTLM()).thenReturn(false);

        // Enable NTLM fallback by providing NTLM creds in constructor
        Kerb5Authenticator auth = new Kerb5Authenticator(new Subject(), "DOM", "user", "pass");
        auth.setForceFallback(true);

        // Token advertising Kerberos mech (so foundKerberos == true), but forceFallback should still route to NTLM
        byte[] init = spnegoInitWithMechs(Kerb5Context.SUPPORTED_MECHS);

        // NtlmPasswordAuthenticator#createContext will inspect mechs and throw because NTLM is not advertised
        SmbUnsupportedOperationException ex =
                assertThrows(SmbUnsupportedOperationException.class, () -> auth.createContext(tc, null, "server.example.com", init, false));
        assertTrue(ex.getMessage().contains("Server does not support NTLM authentication"));

        // Verify the decision consulted the configuration
        // getConfig() is called twice: once in Kerb5Authenticator and once in NtlmPasswordAuthenticator
        verify(tc, times(2)).getConfig();
        verify(config, times(1)).isAllowNTLMFallback();
        verify(config, times(1)).isUseRawNTLM();
    }

    @Test
    @DisplayName("refresh: throws unsupported operation")
    void refresh_throwsUnsupported() {
        Kerb5Authenticator auth = new Kerb5Authenticator((Subject) null);
        SmbUnsupportedOperationException ex = assertThrows(SmbUnsupportedOperationException.class, auth::refresh);
        assertTrue(ex.getMessage().contains("Refreshing credentials is not supported"));
    }

    @Test
    @DisplayName("clone: copies all relevant fields")
    void clone_copiesFields() {
        Subject subj = new Subject();
        Kerb5Authenticator auth = new Kerb5Authenticator(subj, "DOM", "user", "pass");
        auth.setUser("alice");
        auth.setRealm("EXAMPLE.COM");
        auth.setService("cifs");
        auth.setUserLifeTime(123);
        auth.setLifeTime(456);
        auth.setForceFallback(true);

        Kerb5Authenticator cloned = auth.clone();

        assertNotSame(auth, cloned);
        assertEquals(subj, cloned.getSubject());
        assertEquals("alice", cloned.getUser());
        assertEquals("EXAMPLE.COM", cloned.getRealm());
        assertEquals("cifs", cloned.getService());
        assertEquals(123, cloned.getUserLifeTime());
        assertEquals(456, cloned.getLifeTime());

        // toString should include class marker and not throw
        assertTrue(cloned.toString().startsWith("Kerb5Authenticator["));
    }

    @Test
    @DisplayName("equals/hashCode: subject semantics")
    void equalsAndHashCode_subjectSemantics() {
        Kerb5Authenticator a = new Kerb5Authenticator((Subject) null);
        Kerb5Authenticator b = new Kerb5Authenticator((Subject) null);

        // Both null subjects -> equal
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());

        // Mixed null/non-null -> not equal
        Kerb5Authenticator c = new Kerb5Authenticator(new Subject());
        assertNotEquals(a, c);

        // Same subject instance -> equal
        Subject shared = new Subject();
        Kerb5Authenticator d1 = new Kerb5Authenticator(shared);
        Kerb5Authenticator d2 = new Kerb5Authenticator(shared);
        assertEquals(d1, d2);

        // Different type -> false
        assertFalse(a.equals("not-an-auth"));
    }

    @Test
    @DisplayName("isAnonymous: depends on subject presence and super")
    void isAnonymous_behaviour() {
        Kerb5Authenticator anon = new Kerb5Authenticator((Subject) null);
        assertTrue(anon.isAnonymous(), "Null subject with default super should be anonymous");

        Kerb5Authenticator nonAnon = new Kerb5Authenticator(new Subject());
        assertFalse(nonAnon.isAnonymous());
    }

    static Object[][] preferredMechData_nonAnonymous() {
        return new Object[][] { { Kerb5Context.SUPPORTED_MECHS[0], true }, { Kerb5Context.SUPPORTED_MECHS[1], true },
                { new ASN1ObjectIdentifier("1.2.3.4.5"), false } };
    }

    @ParameterizedTest(name = "non-anon preferred mech {0} -> {1}")
    @MethodSource("preferredMechData_nonAnonymous")
    void isPreferredMech_nonAnonymous(ASN1ObjectIdentifier oid, boolean expected) {
        Kerb5Authenticator auth = new Kerb5Authenticator(new Subject());
        assertEquals(expected, auth.isPreferredMech(oid));
    }

    static Object[][] preferredMechData_anonymous() {
        return new Object[][] { { NtlmContext.NTLMSSP_OID, true }, { Kerb5Context.SUPPORTED_MECHS[0], false } };
    }

    @ParameterizedTest(name = "anonymous preferred mech {0} -> {1}")
    @MethodSource("preferredMechData_anonymous")
    void isPreferredMech_anonymous(ASN1ObjectIdentifier oid, boolean expected) {
        Kerb5Authenticator auth = new Kerb5Authenticator((Subject) null);
        assertEquals(expected, auth.isPreferredMech(oid));
    }

    @Test
    @DisplayName("Accessors: user/realm/service and lifetimes")
    void accessors_workAsExpected() {
        Kerb5Authenticator auth = new Kerb5Authenticator((Subject) null);

        // User accessors
        assertNull(auth.getUser());
        auth.setUser(null);
        assertNull(auth.getUser());
        auth.setUser("");
        assertEquals("", auth.getUser());

        // Realm accessors
        assertNull(auth.getRealm());
        auth.setRealm("EXAMPLE.COM");
        assertEquals("EXAMPLE.COM", auth.getRealm());

        // Service accessors
        assertEquals("cifs", auth.getService());
        auth.setService("");
        assertEquals("", auth.getService());

        // Lifetime accessors (edge: zero/negative)
        auth.setUserLifeTime(0);
        assertEquals(0, auth.getUserLifeTime());
        auth.setUserLifeTime(-1);
        assertEquals(-1, auth.getUserLifeTime());

        auth.setLifeTime(0);
        assertEquals(0, auth.getLifeTime());
        auth.setLifeTime(-2);
        assertEquals(-2, auth.getLifeTime());
    }

    @Nested
    class UserDomainTests {
        @Test
        @DisplayName("getUserDomain: derives from KerberosPrincipal in Subject")
        void getUserDomain_fromSubjectPrincipal() {
            Subject subject = new Subject();
            Principal kp = new KerberosPrincipal("alice@EXAMPLE.COM");
            subject.getPrincipals().add(kp);

            Kerb5Authenticator auth = new Kerb5Authenticator(subject);
            assertEquals("EXAMPLE.COM", auth.getUserDomain());
        }

        @Test
        @DisplayName("getUserDomain: explicit realm overrides")
        void getUserDomain_fromExplicitRealm() {
            Kerb5Authenticator auth = new Kerb5Authenticator(new Subject());
            auth.setRealm("REALM.TEST");
            assertEquals("REALM.TEST", auth.getUserDomain());
        }

        @Test
        @DisplayName("getUserDomain: falls back to super domain when no realm/subject")
        void getUserDomain_fallbackToSuper() {
            Kerb5Authenticator auth = new Kerb5Authenticator(null, "DOM", "u", "p");
            // No explicit realm or subject -> returns super.getUserDomain()
            assertEquals("DOM", auth.getUserDomain());
        }
    }

    @Test
    @DisplayName("Protected setSubject: updates subject used by getters")
    void setSubject_updatesSubject() {
        Kerb5Authenticator auth = new Kerb5Authenticator((Subject) null);
        assertNull(auth.getSubject());
        Subject subject = new Subject();
        auth.setSubject(subject);
        assertSame(subject, auth.getSubject());
    }
}
