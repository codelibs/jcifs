package jcifs.pac.kerberos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

/**
 * Test class for KerberosCredentials.
 */
class KerberosCredentialsTest {

    @Mock
    private LoginContext loginContext;

    @Mock
    private Subject subject;

    @Mock
    private KerberosKey key1;

    @Mock
    private KerberosKey key2;

    private static final String LOGIN_CONTEXT_NAME = "TestLoginContext";
    private static final int KEY_TYPE_1 = 1;
    private static final int KEY_TYPE_2 = 2;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    /**
     * Test constructor with a valid login context.
     *
     * @throws LoginException if login fails.
     */
    @Test
    void testConstructor_Success() throws LoginException {
        try (MockedConstruction<LoginContext> mocked = Mockito.mockConstruction(LoginContext.class,
                (mock, context) -> {
                    when(mock.getSubject()).thenReturn(subject);
                    doNothing().when(mock).login();
                })) {
            KerberosCredentials credentials = new KerberosCredentials(LOGIN_CONTEXT_NAME);
            assertNotNull(credentials.getSubject());
            assertEquals(subject, credentials.getSubject());
        }
    }

    /**
     * Test constructor when login fails.
     */
    @Test
    void testConstructor_LoginFailure() {
        assertThrows(LoginException.class, () -> {
            try (MockedConstruction<LoginContext> mocked = Mockito.mockConstruction(LoginContext.class,
                    (mock, context) -> {
                        doThrow(new LoginException("Login failed")).when(mock).login();
                    })) {
                new KerberosCredentials(LOGIN_CONTEXT_NAME);
            }
        });
    }

    /**
     * Test getKeys method when subject has Kerberos keys.
     *
     * @throws LoginException if login fails.
     */
    @Test
    void testGetKeys_WithKeys() throws LoginException {
        Set<Object> privateCredentials = new HashSet<>();
        privateCredentials.add(key1);
        privateCredentials.add(key2);
        when(subject.getPrivateCredentials()).thenReturn(privateCredentials);

        try (MockedConstruction<LoginContext> mocked = Mockito.mockConstruction(LoginContext.class,
                (mock, context) -> {
                    when(mock.getSubject()).thenReturn(subject);
                })) {
            KerberosCredentials credentials = new KerberosCredentials(LOGIN_CONTEXT_NAME);
            KerberosKey[] keys = credentials.getKeys();
            assertEquals(2, keys.length);
        }
    }

    /**
     * Test getKeys method when subject has no Kerberos keys.
     *
     * @throws LoginException if login fails.
     */
    @Test
    void testGetKeys_NoKeys() throws LoginException {
        when(subject.getPrivateCredentials()).thenReturn(Collections.emptySet());

        try (MockedConstruction<LoginContext> mocked = Mockito.mockConstruction(LoginContext.class,
                (mock, context) -> {
                    when(mock.getSubject()).thenReturn(subject);
                })) {
            KerberosCredentials credentials = new KerberosCredentials(LOGIN_CONTEXT_NAME);
            KerberosKey[] keys = credentials.getKeys();
            assertEquals(0, keys.length);
        }
    }

    /**
     * Test getKeys method when subject has other credential types.
     *
     * @throws LoginException if login fails.
     */
    @Test
    void testGetKeys_WithOtherCredentialTypes() throws LoginException {
        Set<Object> privateCredentials = new HashSet<>();
        privateCredentials.add("a string credential");
        privateCredentials.add(12345L);
        when(subject.getPrivateCredentials()).thenReturn(privateCredentials);

        try (MockedConstruction<LoginContext> mocked = Mockito.mockConstruction(LoginContext.class,
                (mock, context) -> {
                    when(mock.getSubject()).thenReturn(subject);
                })) {
            KerberosCredentials credentials = new KerberosCredentials(LOGIN_CONTEXT_NAME);
            KerberosKey[] keys = credentials.getKeys();
            assertEquals(0, keys.length);
        }
    }

    /**
     * Test getKey method when the requested key type exists.
     *
     * @throws LoginException if login fails.
     */
    @Test
    void testGetKey_KeyExists() throws LoginException {
        when(key1.getKeyType()).thenReturn(KEY_TYPE_1);
        when(key2.getKeyType()).thenReturn(KEY_TYPE_2);
        Set<Object> privateCredentials = new HashSet<>();
        privateCredentials.add(key1);
        privateCredentials.add(key2);
        when(subject.getPrivateCredentials()).thenReturn(privateCredentials);

        try (MockedConstruction<LoginContext> mocked = Mockito.mockConstruction(LoginContext.class,
                (mock, context) -> {
                    when(mock.getSubject()).thenReturn(subject);
                })) {
            KerberosCredentials credentials = new KerberosCredentials(LOGIN_CONTEXT_NAME);
            KerberosKey foundKey = credentials.getKey(KEY_TYPE_1);
            assertNotNull(foundKey);
            assertEquals(key1, foundKey);
        }
    }

    /**
     * Test getKey method when the requested key type does not exist.
     *
     * @throws LoginException if login fails.
     */
    @Test
    void testGetKey_KeyDoesNotExist() throws LoginException {
        when(key1.getKeyType()).thenReturn(KEY_TYPE_1);
        Set<Object> privateCredentials = new HashSet<>();
        privateCredentials.add(key1);
        when(subject.getPrivateCredentials()).thenReturn(privateCredentials);

        try (MockedConstruction<LoginContext> mocked = Mockito.mockConstruction(LoginContext.class,
                (mock, context) -> {
                    when(mock.getSubject()).thenReturn(subject);
                })) {
            KerberosCredentials credentials = new KerberosCredentials(LOGIN_CONTEXT_NAME);
            KerberosKey foundKey = credentials.getKey(KEY_TYPE_2);
            assertNull(foundKey);
        }
    }

    /**
     * Test getSubject method.
     *
     * @throws LoginException if login fails.
     */
    @Test
    void testGetSubject() throws LoginException {
        try (MockedConstruction<LoginContext> mocked = Mockito.mockConstruction(LoginContext.class,
                (mock, context) -> {
                    when(mock.getSubject()).thenReturn(subject);
                })) {
            KerberosCredentials credentials = new KerberosCredentials(LOGIN_CONTEXT_NAME);
            assertEquals(subject, credentials.getSubject());
        }
    }
}
