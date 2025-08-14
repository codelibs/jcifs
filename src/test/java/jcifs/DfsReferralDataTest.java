package jcifs;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

/**
 * Test class for DfsReferralData interface functionality
 */
@DisplayName("DfsReferralData Interface Tests")
class DfsReferralDataTest extends BaseTest {

    @Mock
    private DfsReferralData mockReferralData;

    @Test
    @DisplayName("Should define interface methods")
    void testDfsReferralDataInterface() {
        // Verify interface methods exist
        assertDoesNotThrow(() -> {
            mockReferralData.unwrap(DfsReferralData.class);
            mockReferralData.getServer();
            mockReferralData.getDomain();
            mockReferralData.getShare();
            mockReferralData.getPathConsumed();
            mockReferralData.getPath();
            mockReferralData.getExpiration();
            mockReferralData.next();
            mockReferralData.getLink();
        });
    }

    @Test
    @DisplayName("Should get server")
    void testGetServer() {
        // Given
        String server = "testserver";
        when(mockReferralData.getServer()).thenReturn(server);

        // When
        String result = mockReferralData.getServer();

        // Then
        assertEquals(server, result);
        verify(mockReferralData).getServer();
    }

    @Test
    @DisplayName("Should get domain")
    void testGetDomain() {
        // Given
        String domain = "TESTDOMAIN";
        when(mockReferralData.getDomain()).thenReturn(domain);

        // When
        String result = mockReferralData.getDomain();

        // Then
        assertEquals(domain, result);
        verify(mockReferralData).getDomain();
    }

    @Test
    @DisplayName("Should get share")
    void testGetShare() {
        // Given
        String share = "testshare";
        when(mockReferralData.getShare()).thenReturn(share);

        // When
        String result = mockReferralData.getShare();

        // Then
        assertEquals(share, result);
        verify(mockReferralData).getShare();
    }

    @Test
    @DisplayName("Should get path consumed")
    void testGetPathConsumed() {
        // Given
        int pathConsumed = 10;
        when(mockReferralData.getPathConsumed()).thenReturn(pathConsumed);

        // When
        int result = mockReferralData.getPathConsumed();

        // Then
        assertEquals(pathConsumed, result);
        verify(mockReferralData).getPathConsumed();
    }

    @Test
    @DisplayName("Should get path")
    void testGetPath() {
        // Given
        String path = "/test/path";
        when(mockReferralData.getPath()).thenReturn(path);

        // When
        String result = mockReferralData.getPath();

        // Then
        assertEquals(path, result);
        verify(mockReferralData).getPath();
    }

    @Test
    @DisplayName("Should get expiration")
    void testGetExpiration() {
        // Given
        long expiration = System.currentTimeMillis();
        when(mockReferralData.getExpiration()).thenReturn(expiration);

        // When
        long result = mockReferralData.getExpiration();

        // Then
        assertEquals(expiration, result);
        verify(mockReferralData).getExpiration();
    }

    @Test
    @DisplayName("Should get next referral")
    void testNext() {
        // Given
        DfsReferralData nextReferral = mock(DfsReferralData.class);
        when(mockReferralData.next()).thenReturn(nextReferral);

        // When
        DfsReferralData result = mockReferralData.next();

        // Then
        assertEquals(nextReferral, result);
        verify(mockReferralData).next();
    }

    @Test
    @DisplayName("Should get link")
    void testGetLink() {
        // Given
        String link = "/test/link";
        when(mockReferralData.getLink()).thenReturn(link);

        // When
        String result = mockReferralData.getLink();

        // Then
        assertEquals(link, result);
        verify(mockReferralData).getLink();
    }
}
