package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashMap;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class JAASAuthenticatorTest {

    enum SubjectVariant {
        DEFAULT_NO_PS, // configuration null, no preset Subject
        DEFAULT_WITH_PS, // configuration null, but super.getSubject() returns non-null
        WITH_CONFIG // configuration provided via StaticJAASConfiguration
    }

    private JAASAuthenticator buildAuthenticator(SubjectVariant variant) {
        switch (variant) {
        case DEFAULT_WITH_PS: {
            JAASAuthenticator a = new JAASAuthenticator();
            // Provide a preset Subject so the getSubject() path uses the (serviceName, ps, this) constructor
            a.setSubject(new Subject());
            return a;
        }
        case WITH_CONFIG: {
            // Use the constructor that sets a StaticJAASConfiguration to exercise that branch
            return new JAASAuthenticator(new HashMap<String, String>(), "DOM", "user", "pass");
        }
        case DEFAULT_NO_PS:
        default:
            return new JAASAuthenticator();
        }
    }

    @Test
    @DisplayName("isAnonymous and isGuest are always false")
    void testIsAnonymousAndGuestFalse() {
        JAASAuthenticator auth = new JAASAuthenticator();
        // JAAS-based authenticator should never be anonymous or guest
        assertFalse(auth.isAnonymous());
        assertFalse(auth.isGuest());
    }

    @ParameterizedTest
    @EnumSource(SubjectVariant.class)
    @DisplayName("getSubject: handles JAAS failure, caches empty Subject, refresh resets")
    void testGetSubjectLoginFailuresCacheAndRefresh(SubjectVariant variant) throws Exception {
        JAASAuthenticator auth = buildAuthenticator(variant);

        // First call attempts a JAAS login; with no real config, it should fail and return null
        Subject first = auth.getSubject();
        assertNull(first, "First getSubject should return null on JAAS failure");

        // On failure, implementation caches a new empty Subject; second call returns the cached value
        Subject second = auth.getSubject();
        assertNotNull(second, "Second getSubject should return cached Subject after failure");

        // Third call should return the same cached Subject instance
        Subject third = auth.getSubject();
        assertSame(second, third, "Subsequent calls should return same cached Subject instance");

        // Refresh should clear the cache; next call should try to login again and return null (failure)
        auth.refresh();
        Subject afterRefresh = auth.getSubject();
        assertNull(afterRefresh, "After refresh, getSubject should again return null on failure");
    }

    @Test
    @DisplayName("handle: sets NameCallback and PasswordCallback on happy path")
    void testHandleSetsNameAndPasswordHappyPath() throws Exception {
        JAASAuthenticator auth = new JAASAuthenticator("DOM", "user", "pass");
        NameCallback nc = new NameCallback("user:");
        PasswordCallback pc = new PasswordCallback("pass:", false);

        // Exercise callback handler with both callbacks supplied
        Callback[] cbs = new Callback[] { nc, pc };
        auth.handle(cbs);

        // Name should be formatted as username@domain
        assertEquals("user@DOM", nc.getName());
        // Password should be set
        assertEquals("pass", new String(pc.getPassword()));
    }

    @Test
    @DisplayName("handle: sets only provided callbacks (name-only)")
    void testHandleNameOnly() throws Exception {
        JAASAuthenticator auth = new JAASAuthenticator("DOM", "user", "secret");
        NameCallback nc = new NameCallback("user:");
        auth.handle(new Callback[] { nc });
        assertEquals("user@DOM", nc.getName());
    }

    @Test
    @DisplayName("handle: sets only provided callbacks (password-only)")
    void testHandlePasswordOnly() throws Exception {
        JAASAuthenticator auth = new JAASAuthenticator("DOM", "user", "secret");
        PasswordCallback pc = new PasswordCallback("pass:", false);
        auth.handle(new Callback[] { pc });
        assertEquals("secret", new String(pc.getPassword()));
    }

    @Test
    @DisplayName("handle: empty user/domain edge yields '@' and empty password")
    void testHandleWithEmptyUserAndDomainEdge() throws Exception {
        // Default constructor results in empty strings for user, domain, and password
        JAASAuthenticator auth = new JAASAuthenticator();
        NameCallback nc = new NameCallback("user:");
        PasswordCallback pc = new PasswordCallback("pass:", false);

        auth.handle(new Callback[] { nc, pc });

        // With empty strings, code still sets name with '@' separator
        assertEquals("@", nc.getName());
        // Password comes from empty string, which should be an empty char[]
        assertNotNull(pc.getPassword());
        assertEquals(0, pc.getPassword().length);
    }

    @Test
    @DisplayName("handle: null password leaves PasswordCallback unset")
    void testHandleWithNullPasswordDoesNotSet() throws Exception {
        // Spy to override getPassword() to return null
        JAASAuthenticator spyAuth = spy(new JAASAuthenticator("DOM", "user", null));
        when(spyAuth.getPassword()).thenReturn(null);

        PasswordCallback pc = new PasswordCallback("pass:", false);
        spyAuth.handle(new Callback[] { pc });

        // Since getPassword() returned null, handler should not set a password
        assertNull(pc.getPassword());
        verify(spyAuth, times(1)).getPassword();
    }

    @Test
    @DisplayName("clone: copies fields and cached subject; instances are independent")
    void testCloneCopiesFieldsAndIndependence() throws Exception {
        // Use configuration-based constructor to also exercise copying of configuration/service fields
        JAASAuthenticator orig = new JAASAuthenticator(new HashMap<String, String>(), "DOM", "user", "pass");

        // Provide a Subject in super to drive a specific LoginContext constructor branch
        orig.setSubject(new Subject());

        // Trigger a failed login to populate cachedSubject inside orig
        Subject first = orig.getSubject();
        assertNull(first);
        Subject cachedOrig = orig.getSubject();
        assertNotNull(cachedOrig);

        // Clone and verify basic fields copied
        JAASAuthenticator copy = (JAASAuthenticator) orig.clone();
        assertEquals(orig.getUsername(), copy.getUsername());
        assertEquals(orig.getUserDomain(), copy.getUserDomain());
        assertEquals(orig.getPassword(), copy.getPassword());

        // Cached subject is copied and visible via getSubject()
        Subject copySubj = copy.getSubject();
        assertNotNull(copySubj);
        assertSame(cachedOrig, copySubj, "Clone should share the cached Subject reference");

        // Refreshing the original must not clear the clone's cached subject
        orig.refresh();
        assertNull(orig.getSubject(), "Original after refresh should return null (re-attempt login, fail)");
        assertSame(copySubj, copy.getSubject(), "Clone should retain its cached Subject");
    }

    @Test
    @DisplayName("renew: invokes getSubject and returns self")
    void testRenewInvokesGetSubjectAndReturnsSelf() {
        JAASAuthenticator auth = spy(new JAASAuthenticator());
        // Avoid real JAAS by stubbing getSubject
        doReturn(new Subject()).when(auth).getSubject();

        // Act
        CredentialsInternal result = auth.renew();

        // Assert interaction and return value
        assertSame(auth, result);
        verify(auth, times(1)).getSubject();
    }

    @Test
    @DisplayName("renew: returns null when subject renewal fails")
    void testRenewReturnsNullOnFailedSubjectRefresh() {
        JAASAuthenticator auth = spy(new JAASAuthenticator());
        doReturn(null).when(auth).getSubject();

        CredentialsInternal result = auth.renew();

        assertNull(result);
        verify(auth, times(1)).getSubject();
    }
}
