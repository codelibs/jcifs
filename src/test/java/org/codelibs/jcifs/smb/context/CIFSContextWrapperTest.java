package org.codelibs.jcifs.smb.context;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.net.URLStreamHandler;

import org.codelibs.jcifs.smb.BufferCache;
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.Credentials;
import org.codelibs.jcifs.smb.DfsResolver;
import org.codelibs.jcifs.smb.NameServiceClient;
import org.codelibs.jcifs.smb.SidResolver;
import org.codelibs.jcifs.smb.SmbPipeResource;
import org.codelibs.jcifs.smb.SmbResource;
import org.codelibs.jcifs.smb.SmbTransportPool;
import org.codelibs.jcifs.smb.impl.Handler;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.impl.SmbNamedPipe;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CIFSContextWrapperTest {

    private CIFSContext mockDelegate;
    private Configuration mockConfiguration;
    private CIFSContextWrapper cifsContextWrapper;

    @BeforeEach
    void setUp() {
        mockDelegate = mock(CIFSContext.class);
        mockConfiguration = mock(Configuration.class);
        when(mockDelegate.getConfig()).thenReturn(mockConfiguration);
        when(mockConfiguration.isTraceResourceUsage()).thenReturn(false); // Default to false or true based on expected behavior
        cifsContextWrapper = new CIFSContextWrapper(mockDelegate);
    }

    @Test
    void testConstructor() {
        // Verify that the delegate is correctly set
        assertNotNull(cifsContextWrapper);
    }

    @Test
    void testGetSmbResource() throws CIFSException, MalformedURLException {
        // Test get(String url) method
        String url = "smb://server/share/file.txt";
        SmbResource mockSmbResource = mock(SmbFile.class);
        // Mocking SmbFile constructor is tricky, so we'll just verify the call to the delegate
        // and ensure no exception is thrown for a valid URL.
        // The actual SmbFile creation is outside the scope of this wrapper's direct responsibility.

        // For coverage, we'll ensure the method doesn't throw MalformedURLException for a valid URL
        // and that it attempts to create an SmbFile.
        // We cannot directly mock `new SmbFile()`, so we rely on the fact that if it doesn't throw, it's working as expected.

        // This test primarily ensures that the wrapper correctly handles the MalformedURLException
        // and delegates the SmbFile creation.

        // When a valid URL is provided, it should not throw an exception.
        assertNotNull(cifsContextWrapper.get(url));
    }

    @Test
    void testGetSmbResource_MalformedURLException() {
        // Test get(String url) with a malformed URL
        String malformedUrl = "invalid-url";
        CIFSException thrown = assertThrows(CIFSException.class, () -> {
            cifsContextWrapper.get(malformedUrl);
        });
        assertTrue(thrown.getMessage().contains("Invalid URL"));
        assertTrue(thrown.getCause() instanceof MalformedURLException);
    }

    @Test
    void testGetPipe() throws CIFSException, MalformedURLException {
        // Test getPipe(String url, int pipeType) method
        String url = "smb://server/IPC$/pipeName"; // Corrected URL for named pipe
        int pipeType = 1;
        SmbPipeResource mockSmbPipeResource = mock(SmbNamedPipe.class);

        // Similar to testGetSmbResource, we cannot directly mock `new SmbNamedPipe()`.
        // We verify that no exception is thrown for a valid URL and that it attempts to create an SmbNamedPipe.
        assertNotNull(cifsContextWrapper.getPipe(url, pipeType));
    }

    @Test
    void testGetPipe_MalformedURLException() {
        // Test getPipe(String url, int pipeType) with a malformed URL
        String malformedUrl = "invalid-pipe-url";
        int pipeType = 1;
        CIFSException thrown = assertThrows(CIFSException.class, () -> {
            cifsContextWrapper.getPipe(malformedUrl, pipeType);
        });
        assertTrue(thrown.getMessage().contains("Invalid URL"));
        assertTrue(thrown.getCause() instanceof MalformedURLException);
    }

    @Test
    void testGetConfig() {
        // Test getConfig() method
        Configuration mockConfig = mock(Configuration.class);
        when(mockDelegate.getConfig()).thenReturn(mockConfig);
        assertEquals(mockConfig, cifsContextWrapper.getConfig());
        verify(mockDelegate).getConfig();
    }

    @Test
    void testGetDfs() {
        // Test getDfs() method
        DfsResolver mockDfsResolver = mock(DfsResolver.class);
        when(mockDelegate.getDfs()).thenReturn(mockDfsResolver);
        assertEquals(mockDfsResolver, cifsContextWrapper.getDfs());
        verify(mockDelegate).getDfs();
    }

    @Test
    void testGetCredentials() {
        // Test getCredentials() method
        Credentials mockCredentials = mock(Credentials.class);
        when(mockDelegate.getCredentials()).thenReturn(mockCredentials);
        assertEquals(mockCredentials, cifsContextWrapper.getCredentials());
        verify(mockDelegate).getCredentials();
    }

    @Test
    void testGetUrlHandler() {
        // Test getUrlHandler() method
        // First call should create a new Handler
        URLStreamHandler handler1 = cifsContextWrapper.getUrlHandler();
        assertNotNull(handler1);
        assertTrue(handler1 instanceof Handler);

        // Second call should return the same instance
        URLStreamHandler handler2 = cifsContextWrapper.getUrlHandler();
        assertEquals(handler1, handler2);
    }

    @Test
    void testGetSIDResolver() {
        // Test getSIDResolver() method
        SidResolver mockSidResolver = mock(SidResolver.class);
        when(mockDelegate.getSIDResolver()).thenReturn(mockSidResolver);
        assertEquals(mockSidResolver, cifsContextWrapper.getSIDResolver());
        verify(mockDelegate).getSIDResolver();
    }

    @Test
    void testHasDefaultCredentials_True() {
        // Test hasDefaultCredentials() method when true
        when(mockDelegate.hasDefaultCredentials()).thenReturn(true);
        assertTrue(cifsContextWrapper.hasDefaultCredentials());
        verify(mockDelegate).hasDefaultCredentials();
    }

    @Test
    void testHasDefaultCredentials_False() {
        // Test hasDefaultCredentials() method when false
        when(mockDelegate.hasDefaultCredentials()).thenReturn(false);
        assertFalse(cifsContextWrapper.hasDefaultCredentials());
        verify(mockDelegate).hasDefaultCredentials();
    }

    @Test
    void testWithCredentials() {
        // Test withCredentials(Credentials creds) method
        Credentials mockCredentials = mock(Credentials.class);
        CIFSContext mockNewContext = mock(CIFSContext.class);
        when(mockDelegate.withCredentials(mockCredentials)).thenReturn(mockNewContext);
        assertEquals(mockNewContext, cifsContextWrapper.withCredentials(mockCredentials));
        verify(mockDelegate).withCredentials(mockCredentials);
    }

    @Test
    void testWithDefaultCredentials() {
        // Test withDefaultCredentials() method
        CIFSContext mockNewContext = mock(CIFSContext.class);
        when(mockDelegate.withDefaultCredentials()).thenReturn(mockNewContext);
        assertEquals(mockNewContext, cifsContextWrapper.withDefaultCredentials());
        verify(mockDelegate).withDefaultCredentials();
    }

    @Test
    void testWithAnonymousCredentials() {
        // Test withAnonymousCredentials() method
        CIFSContext mockNewContext = mock(CIFSContext.class);
        when(mockDelegate.withAnonymousCredentials()).thenReturn(mockNewContext);
        assertEquals(mockNewContext, cifsContextWrapper.withAnonymousCredentials());
        verify(mockDelegate).withAnonymousCredentials();
    }

    @Test
    void testWithGuestCrendentials() {
        // Test withGuestCrendentials() method
        CIFSContext mockNewContext = mock(CIFSContext.class);
        when(mockDelegate.withGuestCrendentials()).thenReturn(mockNewContext);
        assertEquals(mockNewContext, cifsContextWrapper.withGuestCrendentials());
        verify(mockDelegate).withGuestCrendentials();
    }

    @Test
    void testRenewCredentials_True() {
        // Test renewCredentials(String locationHint, Throwable error) method when true
        String locationHint = "testLocation";
        Throwable error = new RuntimeException("testError");
        when(mockDelegate.renewCredentials(locationHint, error)).thenReturn(true);
        assertTrue(cifsContextWrapper.renewCredentials(locationHint, error));
        verify(mockDelegate).renewCredentials(locationHint, error);
    }

    @Test
    void testRenewCredentials_False() {
        // Test renewCredentials(String locationHint, Throwable error) method when false
        String locationHint = "testLocation";
        Throwable error = new RuntimeException("testError");
        when(mockDelegate.renewCredentials(locationHint, error)).thenReturn(false);
        assertFalse(cifsContextWrapper.renewCredentials(locationHint, error));
        verify(mockDelegate).renewCredentials(locationHint, error);
    }

    @Test
    void testGetNameServiceClient() {
        // Test getNameServiceClient() method
        NameServiceClient mockNameServiceClient = mock(NameServiceClient.class);
        when(mockDelegate.getNameServiceClient()).thenReturn(mockNameServiceClient);
        assertEquals(mockNameServiceClient, cifsContextWrapper.getNameServiceClient());
        verify(mockDelegate).getNameServiceClient();
    }

    @Test
    void testGetBufferCache() {
        // Test getBufferCache() method
        BufferCache mockBufferCache = mock(BufferCache.class);
        when(mockDelegate.getBufferCache()).thenReturn(mockBufferCache);
        assertEquals(mockBufferCache, cifsContextWrapper.getBufferCache());
        verify(mockDelegate).getBufferCache();
    }

    @Test
    void testGetTransportPool() {
        // Test getTransportPool() method
        SmbTransportPool mockSmbTransportPool = mock(SmbTransportPool.class);
        when(mockDelegate.getTransportPool()).thenReturn(mockSmbTransportPool);
        assertEquals(mockSmbTransportPool, cifsContextWrapper.getTransportPool());
        verify(mockDelegate).getTransportPool();
    }

    @Test
    void testClose_True() throws CIFSException {
        // Test close() method when true
        when(mockDelegate.close()).thenReturn(true);
        assertTrue(cifsContextWrapper.close());
        verify(mockDelegate).close();
    }

    @Test
    void testClose_False() throws CIFSException {
        // Test close() method when false
        when(mockDelegate.close()).thenReturn(false);
        assertFalse(cifsContextWrapper.close());
        verify(mockDelegate).close();
    }
}
