package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URLStreamHandler;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

/**
 * Test class for CIFSContext interface functionality
 */
@DisplayName("CIFSContext Tests")
class CIFSContextTest extends BaseTest {

    @Mock
    private CIFSContext mockContext;

    @Test
    @DisplayName("Should define interface methods")
    void testCIFSContextInterface() {
        // Verify interface methods exist
        assertDoesNotThrow(() -> {
            mockContext.get("smb://server/share");
            mockContext.getPipe("smb://server/share/pipe", 0);
            mockContext.close();
            mockContext.getConfig();
            mockContext.getNameServiceClient();
            mockContext.getBufferCache();
            mockContext.getTransportPool();
            mockContext.getDfs();
            mockContext.getSIDResolver();
            mockContext.getCredentials();
            mockContext.getUrlHandler();
            mockContext.hasDefaultCredentials();
            mockContext.withDefaultCredentials();
            mockContext.withAnonymousCredentials();
            mockContext.withGuestCrendentials();
            mockContext.withCredentials(mock(Credentials.class));
            mockContext.renewCredentials("hint", new Exception());
        });
    }

    @Test
    @DisplayName("Should get SmbResource")
    void testGet() throws CIFSException {
        // Given
        String url = "smb://server/share/file";
        SmbResource mockResource = mock(SmbResource.class);
        when(mockContext.get(url)).thenReturn(mockResource);

        // When
        SmbResource resource = mockContext.get(url);

        // Then
        assertEquals(mockResource, resource);
        verify(mockContext).get(url);
    }

    @Test
    @DisplayName("Should get SmbPipeResource")
    void testGetPipe() throws CIFSException {
        // Given
        String url = "smb://server/share/pipe";
        int pipeType = 1;
        SmbPipeResource mockPipe = mock(SmbPipeResource.class);
        when(mockContext.getPipe(url, pipeType)).thenReturn(mockPipe);

        // When
        SmbPipeResource pipe = mockContext.getPipe(url, pipeType);

        // Then
        assertEquals(mockPipe, pipe);
        verify(mockContext).getPipe(url, pipeType);
    }

    @Test
    @DisplayName("Should close context")
    void testClose() throws CIFSException {
        // When
        mockContext.close();

        // Then
        verify(mockContext).close();
    }

    @Test
    @DisplayName("Should get Configuration")
    void testGetConfig() {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        when(mockContext.getConfig()).thenReturn(mockConfig);

        // When
        Configuration config = mockContext.getConfig();

        // Then
        assertEquals(mockConfig, config);
        verify(mockContext).getConfig();
    }

    @Test
    @DisplayName("Should get NameServiceClient")
    void testGetNameServiceClient() {
        // Given
        NameServiceClient mockClient = mock(NameServiceClient.class);
        when(mockContext.getNameServiceClient()).thenReturn(mockClient);

        // When
        NameServiceClient client = mockContext.getNameServiceClient();

        // Then
        assertEquals(mockClient, client);
        verify(mockContext).getNameServiceClient();
    }

    @Test
    @DisplayName("Should get BufferCache")
    void testGetBufferCache() {
        // Given
        BufferCache mockCache = mock(BufferCache.class);
        when(mockContext.getBufferCache()).thenReturn(mockCache);

        // When
        BufferCache cache = mockContext.getBufferCache();

        // Then
        assertEquals(mockCache, cache);
        verify(mockContext).getBufferCache();
    }

    @Test
    @DisplayName("Should get SmbTransportPool")
    void testGetTransportPool() {
        // Given
        SmbTransportPool mockPool = mock(SmbTransportPool.class);
        when(mockContext.getTransportPool()).thenReturn(mockPool);

        // When
        SmbTransportPool pool = mockContext.getTransportPool();

        // Then
        assertEquals(mockPool, pool);
        verify(mockContext).getTransportPool();
    }

    @Test
    @DisplayName("Should get DfsResolver")
    void testGetDfs() {
        // Given
        DfsResolver mockResolver = mock(DfsResolver.class);
        when(mockContext.getDfs()).thenReturn(mockResolver);

        // When
        DfsResolver resolver = mockContext.getDfs();

        // Then
        assertEquals(mockResolver, resolver);
        verify(mockContext).getDfs();
    }

    @Test
    @DisplayName("Should get SidResolver")
    void testGetSIDResolver() {
        // Given
        SidResolver mockResolver = mock(SidResolver.class);
        when(mockContext.getSIDResolver()).thenReturn(mockResolver);

        // When
        SidResolver resolver = mockContext.getSIDResolver();

        // Then
        assertEquals(mockResolver, resolver);
        verify(mockContext).getSIDResolver();
    }

    @Test
    @DisplayName("Should get Credentials")
    void testGetCredentials() {
        // Given
        Credentials mockCreds = mock(Credentials.class);
        when(mockContext.getCredentials()).thenReturn(mockCreds);

        // When
        Credentials creds = mockContext.getCredentials();

        // Then
        assertEquals(mockCreds, creds);
        verify(mockContext).getCredentials();
    }

    @Test
    @DisplayName("Should get URLStreamHandler")
    void testGetUrlHandler() {
        // Given
        URLStreamHandler mockHandler = mock(URLStreamHandler.class);
        when(mockContext.getUrlHandler()).thenReturn(mockHandler);

        // When
        URLStreamHandler handler = mockContext.getUrlHandler();

        // Then
        assertEquals(mockHandler, handler);
        verify(mockContext).getUrlHandler();
    }

    @Test
    @DisplayName("Should check for default credentials")
    void testHasDefaultCredentials() {
        // Given
        when(mockContext.hasDefaultCredentials()).thenReturn(true);

        // When
        boolean hasCreds = mockContext.hasDefaultCredentials();

        // Then
        assertTrue(hasCreds);
        verify(mockContext).hasDefaultCredentials();
    }

    @Test
    @DisplayName("Should get context with default credentials")
    void testWithDefaultCredentials() {
        // Given
        CIFSContext newContext = mock(CIFSContext.class);
        when(mockContext.withDefaultCredentials()).thenReturn(newContext);

        // When
        CIFSContext context = mockContext.withDefaultCredentials();

        // Then
        assertEquals(newContext, context);
        verify(mockContext).withDefaultCredentials();
    }

    @Test
    @DisplayName("Should get context with anonymous credentials")
    void testWithAnonymousCredentials() {
        // Given
        CIFSContext newContext = mock(CIFSContext.class);
        when(mockContext.withAnonymousCredentials()).thenReturn(newContext);

        // When
        CIFSContext context = mockContext.withAnonymousCredentials();

        // Then
        assertEquals(newContext, context);
        verify(mockContext).withAnonymousCredentials();
    }

    @Test
    @DisplayName("Should get context with guest credentials")
    void testWithGuestCrendentials() {
        // Given
        CIFSContext newContext = mock(CIFSContext.class);
        when(mockContext.withGuestCrendentials()).thenReturn(newContext);

        // When
        CIFSContext context = mockContext.withGuestCrendentials();

        // Then
        assertEquals(newContext, context);
        verify(mockContext).withGuestCrendentials();
    }

    @Test
    @DisplayName("Should get context with specific credentials")
    void testWithCredentials() {
        // Given
        Credentials creds = mock(Credentials.class);
        CIFSContext newContext = mock(CIFSContext.class);
        when(mockContext.withCredentials(creds)).thenReturn(newContext);

        // When
        CIFSContext context = mockContext.withCredentials(creds);

        // Then
        assertEquals(newContext, context);
        verify(mockContext).withCredentials(creds);
    }

    @Test
    @DisplayName("Should renew credentials")
    void testRenewCredentials() {
        // Given
        String hint = "hint";
        Throwable error = new Exception();
        when(mockContext.renewCredentials(hint, error)).thenReturn(true);

        // When
        boolean renewed = mockContext.renewCredentials(hint, error);

        // Then
        assertTrue(renewed);
        verify(mockContext).renewCredentials(hint, error);
    }
}
