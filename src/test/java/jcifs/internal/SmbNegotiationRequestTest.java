package jcifs.internal;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Test class for SmbNegotiationRequest interface
 */
@ExtendWith(MockitoExtension.class)
class SmbNegotiationRequestTest {

    @Mock
    private SmbNegotiationRequest negotiationRequest;

    private SmbNegotiationRequest customImplementation;

    @BeforeEach
    void setUp() {
        // Create a custom implementation for additional testing
        customImplementation = new TestSmbNegotiationRequest(false);
    }

    @Test
    @DisplayName("Test isSigningEnforced returns true when signing is enforced")
    void testIsSigningEnforcedReturnsTrue() {
        // Given
        when(negotiationRequest.isSigningEnforced()).thenReturn(true);

        // When
        boolean result = negotiationRequest.isSigningEnforced();

        // Then
        assertTrue(result, "isSigningEnforced should return true when signing is enforced");
        verify(negotiationRequest, times(1)).isSigningEnforced();
    }

    @Test
    @DisplayName("Test isSigningEnforced returns false when signing is not enforced")
    void testIsSigningEnforcedReturnsFalse() {
        // Given
        when(negotiationRequest.isSigningEnforced()).thenReturn(false);

        // When
        boolean result = negotiationRequest.isSigningEnforced();

        // Then
        assertFalse(result, "isSigningEnforced should return false when signing is not enforced");
        verify(negotiationRequest, times(1)).isSigningEnforced();
    }

    @Test
    @DisplayName("Test multiple calls to isSigningEnforced")
    void testMultipleCallsToIsSigningEnforced() {
        // Given
        when(negotiationRequest.isSigningEnforced())
            .thenReturn(true)
            .thenReturn(false)
            .thenReturn(true);

        // When & Then
        assertTrue(negotiationRequest.isSigningEnforced(), "First call should return true");
        assertFalse(negotiationRequest.isSigningEnforced(), "Second call should return false");
        assertTrue(negotiationRequest.isSigningEnforced(), "Third call should return true");

        verify(negotiationRequest, times(3)).isSigningEnforced();
    }

    @Test
    @DisplayName("Test custom implementation with signing not enforced")
    void testCustomImplementationSigningNotEnforced() {
        // Given
        SmbNegotiationRequest request = new TestSmbNegotiationRequest(false);

        // When
        boolean result = request.isSigningEnforced();

        // Then
        assertFalse(result, "Custom implementation should return false when initialized with false");
    }

    @Test
    @DisplayName("Test custom implementation with signing enforced")
    void testCustomImplementationSigningEnforced() {
        // Given
        SmbNegotiationRequest request = new TestSmbNegotiationRequest(true);

        // When
        boolean result = request.isSigningEnforced();

        // Then
        assertTrue(result, "Custom implementation should return true when initialized with true");
    }

    @Test
    @DisplayName("Test interface can be mocked")
    void testInterfaceCanBeMocked() {
        // Given
        SmbNegotiationRequest mockRequest = mock(SmbNegotiationRequest.class);

        // Then
        assertNotNull(mockRequest, "Mock should be created successfully");
    }

    @Test
    @DisplayName("Test default behavior of mock without stubbing")
    void testDefaultBehaviorOfMock() {
        // Given
        SmbNegotiationRequest mockRequest = mock(SmbNegotiationRequest.class);

        // When
        boolean result = mockRequest.isSigningEnforced();

        // Then
        assertFalse(result, "Mock should return false by default for boolean methods");
    }

    @Test
    @DisplayName("Test implementation consistency")
    void testImplementationConsistency() {
        // Given
        SmbNegotiationRequest consistentRequest = new TestSmbNegotiationRequest(true);

        // When & Then - verify consistency across multiple calls
        for (int i = 0; i < 10; i++) {
            assertTrue(consistentRequest.isSigningEnforced(), 
                "Implementation should consistently return the same value");
        }
    }

    @Test
    @DisplayName("Test different implementations can have different behaviors")
    void testDifferentImplementations() {
        // Given
        SmbNegotiationRequest enforcedRequest = new TestSmbNegotiationRequest(true);
        SmbNegotiationRequest notEnforcedRequest = new TestSmbNegotiationRequest(false);

        // When & Then
        assertTrue(enforcedRequest.isSigningEnforced(), 
            "Enforced request should return true");
        assertFalse(notEnforcedRequest.isSigningEnforced(), 
            "Not enforced request should return false");
    }

    @Test
    @DisplayName("Test anonymous class implementation")
    void testAnonymousClassImplementation() {
        // Given
        SmbNegotiationRequest anonymousRequest = new SmbNegotiationRequest() {
            @Override
            public boolean isSigningEnforced() {
                return true;
            }
        };

        // When
        boolean result = anonymousRequest.isSigningEnforced();

        // Then
        assertTrue(result, "Anonymous implementation should return true");
    }

    @Test
    @DisplayName("Test lambda implementation (if applicable)")
    void testLambdaImplementation() {
        // Given - Using a functional interface pattern
        SmbNegotiationRequest lambdaRequest = () -> true;

        // When
        boolean result = lambdaRequest.isSigningEnforced();

        // Then
        assertTrue(result, "Lambda implementation should return true");
    }

    /**
     * Test implementation of SmbNegotiationRequest for testing purposes
     */
    private static class TestSmbNegotiationRequest implements SmbNegotiationRequest {
        private final boolean signingEnforced;

        TestSmbNegotiationRequest(boolean signingEnforced) {
            this.signingEnforced = signingEnforced;
        }

        @Override
        public boolean isSigningEnforced() {
            return signingEnforced;
        }
    }
}
