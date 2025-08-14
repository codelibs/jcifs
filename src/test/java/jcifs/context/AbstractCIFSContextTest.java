package jcifs.context;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URLStreamHandler;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.BufferCache;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.Credentials;
import jcifs.DfsResolver;
import jcifs.NameServiceClient;
import jcifs.SidResolver;
import jcifs.SmbPipeResource;
import jcifs.SmbResource;
import jcifs.SmbTransportPool;
import jcifs.smb.NtlmPasswordAuthenticator;

class AbstractCIFSContextTest {

    private TestAbstractCIFSContext context;

    @Mock
    private Credentials mockCredentials;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        context = new TestAbstractCIFSContext(mockCredentials);
    }

    // Concrete implementation for testing AbstractCIFSContext
    private static class TestAbstractCIFSContext extends AbstractCIFSContext {
        private final Credentials defaultCreds;
        private boolean closeCalled = false;

        public TestAbstractCIFSContext(Credentials defaultCreds) {
            this.defaultCreds = defaultCreds;
        }

        @Override
        protected Credentials getDefaultCredentials() {
            return defaultCreds;
        }

        @Override
        public boolean close() throws CIFSException {
            closeCalled = true;
            // Call super.close() to ensure the shutdown hook is removed
            return super.close();
        }

        public boolean isCloseCalled() {
            return closeCalled;
        }

        @Override
        public URLStreamHandler getUrlHandler() {
            return null; // Not relevant for AbstractCIFSContext tests
        }

        @Override
        public SidResolver getSIDResolver() {
            return null; // Not relevant for AbstractCIFSContext tests
        }

        @Override
        public DfsResolver getDfs() {
            return null; // Not relevant for AbstractCIFSContext tests
        }

        @Override
        public SmbTransportPool getTransportPool() {
            return null; // Not relevant for AbstractCIFSContext tests
        }

        @Override
        public BufferCache getBufferCache() {
            return null; // Not relevant for AbstractCIFSContext tests
        }

        @Override
        public NameServiceClient getNameServiceClient() {
            return null; // Not relevant for AbstractCIFSContext tests
        }

        @Override
        public Configuration getConfig() {
            return null; // Not relevant for AbstractCIFSContext tests
        }

        @Override
        public SmbPipeResource getPipe(String name, int flags) {
            return null; // Not relevant for AbstractCIFSContext tests
        }

        @Override
        public SmbResource get(String key) {
            return null; // Not relevant for AbstractCIFSContext tests
        }
    }

    @Test
    void testWithCredentials() {
        Credentials newCreds = mock(Credentials.class);
        CIFSContext wrappedContext = context.withCredentials(newCreds);

        assertNotNull(wrappedContext);
        assertTrue(wrappedContext instanceof CIFSContextCredentialWrapper);
        // Verify that the new context uses the provided credentials
        assertEquals(newCreds, wrappedContext.getCredentials());
    }

    @Test
    void testWithAnonymousCredentials() {
        CIFSContext wrappedContext = context.withAnonymousCredentials();

        assertNotNull(wrappedContext);
        assertTrue(wrappedContext instanceof CIFSContextCredentialWrapper);
        // Verify that the new context uses NtlmPasswordAuthenticator (anonymous)
        assertTrue(wrappedContext.getCredentials() instanceof NtlmPasswordAuthenticator);
        assertTrue(wrappedContext.getCredentials().isAnonymous());
    }

    @Test
    void testWithDefaultCredentials() {
        CIFSContext wrappedContext = context.withDefaultCredentials();

        assertNotNull(wrappedContext);
        assertTrue(wrappedContext instanceof CIFSContextCredentialWrapper);
        // Verify that the new context uses the default credentials provided to the test context
        assertEquals(mockCredentials, wrappedContext.getCredentials());
    }

    @Test
    void testWithGuestCredentials() {
        CIFSContext wrappedContext = context.withGuestCrendentials();

        assertNotNull(wrappedContext);
        assertTrue(wrappedContext instanceof CIFSContextCredentialWrapper);
        // Verify that the new context uses NtlmPasswordAuthenticator (guest)
        assertTrue(wrappedContext.getCredentials() instanceof NtlmPasswordAuthenticator);
        assertTrue(wrappedContext.getCredentials().isGuest());
    }

    @Test
    void testGetCredentials() {
        assertEquals(mockCredentials, context.getCredentials());
    }

    @Test
    void testHasDefaultCredentials_withNonAnonymous() {
        when(mockCredentials.isAnonymous()).thenReturn(false);
        assertTrue(context.hasDefaultCredentials());
    }

    @Test
    void testHasDefaultCredentials_withAnonymous() {
        when(mockCredentials.isAnonymous()).thenReturn(true);
        assertFalse(context.hasDefaultCredentials());
    }

    @Test
    void testHasDefaultCredentials_withNull() {
        context = new TestAbstractCIFSContext(null); // Test with null credentials
        assertFalse(context.hasDefaultCredentials());
    }

    @Test
    void testRenewCredentials() {
        assertFalse(context.renewCredentials("someLocation", new Exception("someError")));
    }

    @Test
    void testClose() throws CIFSException {
        assertFalse(context.isCloseCalled());

        boolean result = context.close();

        assertFalse(result); // AbstractCIFSContext always returns false for close()
        assertTrue(context.isCloseCalled());
    }

    @Test
    void testRun_successfulClose() throws CIFSException {
        // Simulate the shutdown hook being run
        context.run();

        assertTrue(context.isCloseCalled()); // Verify close() was called
    }

    @Test
    void testRun_closeThrowsException() throws CIFSException {
        // Create a spy on the context to make close() throw an exception
        TestAbstractCIFSContext spyContext = new TestAbstractCIFSContext(mockCredentials) {
            @Override
            public boolean close() throws CIFSException {
                super.close(); // Call original close to set closeCalled
                throw new CIFSException("Test exception during close");
            }
        };

        // Simulate the shutdown hook being run
        spyContext.run();

        assertTrue(spyContext.isCloseCalled()); // Verify close() was called
        // We can't directly assert on log.warn, but we've covered the path
    }
}