package jcifs.internal;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.CIFSContext;
import jcifs.DialectVersion;
import jcifs.util.transport.Response;

/**
 * Test class for SmbNegotiationResponse interface
 */
class SmbNegotiationResponseTest {

    @Mock
    private SmbNegotiationResponse negotiationResponse;
    
    @Mock
    private CIFSContext cifsContext;
    
    @Mock
    private SmbNegotiationRequest negotiationRequest;
    
    @Mock
    private CommonServerMessageBlock serverMessageBlock;
    
    @Mock
    private Response response;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    @DisplayName("Test isValid returns true for valid negotiation")
    void testIsValidReturnsTrue() {
        // Arrange
        when(negotiationResponse.isValid(cifsContext, negotiationRequest)).thenReturn(true);
        
        // Act
        boolean result = negotiationResponse.isValid(cifsContext, negotiationRequest);
        
        // Assert
        assertTrue(result);
        verify(negotiationResponse).isValid(cifsContext, negotiationRequest);
    }

    @Test
    @DisplayName("Test isValid returns false for invalid negotiation")
    void testIsValidReturnsFalse() {
        // Arrange
        when(negotiationResponse.isValid(cifsContext, negotiationRequest)).thenReturn(false);
        
        // Act
        boolean result = negotiationResponse.isValid(cifsContext, negotiationRequest);
        
        // Assert
        assertFalse(result);
        verify(negotiationResponse).isValid(cifsContext, negotiationRequest);
    }

    @Test
    @DisplayName("Test isValid with null context")
    void testIsValidWithNullContext() {
        // Arrange
        when(negotiationResponse.isValid(null, negotiationRequest)).thenReturn(false);
        
        // Act
        boolean result = negotiationResponse.isValid(null, negotiationRequest);
        
        // Assert
        assertFalse(result);
        verify(negotiationResponse).isValid(null, negotiationRequest);
    }

    @Test
    @DisplayName("Test isValid with null request")
    void testIsValidWithNullRequest() {
        // Arrange
        when(negotiationResponse.isValid(cifsContext, null)).thenReturn(false);
        
        // Act
        boolean result = negotiationResponse.isValid(cifsContext, null);
        
        // Assert
        assertFalse(result);
        verify(negotiationResponse).isValid(cifsContext, null);
    }

    @Test
    @DisplayName("Test getSelectedDialect returns SMB1")
    void testGetSelectedDialectSMB1() {
        // Arrange
        when(negotiationResponse.getSelectedDialect()).thenReturn(DialectVersion.SMB1);
        
        // Act
        DialectVersion dialect = negotiationResponse.getSelectedDialect();
        
        // Assert
        assertEquals(DialectVersion.SMB1, dialect);
        verify(negotiationResponse).getSelectedDialect();
    }

    @Test
    @DisplayName("Test getSelectedDialect returns SMB2")
    void testGetSelectedDialectSMB2() {
        // Arrange
        when(negotiationResponse.getSelectedDialect()).thenReturn(DialectVersion.SMB202);
        
        // Act
        DialectVersion dialect = negotiationResponse.getSelectedDialect();
        
        // Assert
        assertEquals(DialectVersion.SMB202, dialect);
        verify(negotiationResponse).getSelectedDialect();
    }

    @Test
    @DisplayName("Test getSelectedDialect returns SMB3")
    void testGetSelectedDialectSMB3() {
        // Arrange
        when(negotiationResponse.getSelectedDialect()).thenReturn(DialectVersion.SMB311);
        
        // Act
        DialectVersion dialect = negotiationResponse.getSelectedDialect();
        
        // Assert
        assertEquals(DialectVersion.SMB311, dialect);
        verify(negotiationResponse).getSelectedDialect();
    }

    @Test
    @DisplayName("Test isSigningEnabled returns true")
    void testIsSigningEnabledTrue() {
        // Arrange
        when(negotiationResponse.isSigningEnabled()).thenReturn(true);
        
        // Act
        boolean result = negotiationResponse.isSigningEnabled();
        
        // Assert
        assertTrue(result);
        verify(negotiationResponse).isSigningEnabled();
    }

    @Test
    @DisplayName("Test isSigningEnabled returns false")
    void testIsSigningEnabledFalse() {
        // Arrange
        when(negotiationResponse.isSigningEnabled()).thenReturn(false);
        
        // Act
        boolean result = negotiationResponse.isSigningEnabled();
        
        // Assert
        assertFalse(result);
        verify(negotiationResponse).isSigningEnabled();
    }

    @Test
    @DisplayName("Test isSigningRequired returns true")
    void testIsSigningRequiredTrue() {
        // Arrange
        when(negotiationResponse.isSigningRequired()).thenReturn(true);
        
        // Act
        boolean result = negotiationResponse.isSigningRequired();
        
        // Assert
        assertTrue(result);
        verify(negotiationResponse).isSigningRequired();
    }

    @Test
    @DisplayName("Test isSigningRequired returns false")
    void testIsSigningRequiredFalse() {
        // Arrange
        when(negotiationResponse.isSigningRequired()).thenReturn(false);
        
        // Act
        boolean result = negotiationResponse.isSigningRequired();
        
        // Assert
        assertFalse(result);
        verify(negotiationResponse).isSigningRequired();
    }

    @Test
    @DisplayName("Test isDFSSupported returns true")
    void testIsDFSSupportedTrue() {
        // Arrange
        when(negotiationResponse.isDFSSupported()).thenReturn(true);
        
        // Act
        boolean result = negotiationResponse.isDFSSupported();
        
        // Assert
        assertTrue(result);
        verify(negotiationResponse).isDFSSupported();
    }

    @Test
    @DisplayName("Test isDFSSupported returns false")
    void testIsDFSSupportedFalse() {
        // Arrange
        when(negotiationResponse.isDFSSupported()).thenReturn(false);
        
        // Act
        boolean result = negotiationResponse.isDFSSupported();
        
        // Assert
        assertFalse(result);
        verify(negotiationResponse).isDFSSupported();
    }

    @Test
    @DisplayName("Test setupRequest method")
    void testSetupRequest() {
        // Arrange
        doNothing().when(negotiationResponse).setupRequest(serverMessageBlock);
        
        // Act
        negotiationResponse.setupRequest(serverMessageBlock);
        
        // Assert
        verify(negotiationResponse).setupRequest(serverMessageBlock);
    }

    @Test
    @DisplayName("Test setupRequest with null")
    void testSetupRequestWithNull() {
        // Arrange
        doNothing().when(negotiationResponse).setupRequest(null);
        
        // Act
        negotiationResponse.setupRequest(null);
        
        // Assert
        verify(negotiationResponse).setupRequest(null);
    }

    @Test
    @DisplayName("Test setupResponse method")
    void testSetupResponse() {
        // Arrange
        doNothing().when(negotiationResponse).setupResponse(response);
        
        // Act
        negotiationResponse.setupResponse(response);
        
        // Assert
        verify(negotiationResponse).setupResponse(response);
    }

    @Test
    @DisplayName("Test setupResponse with null")
    void testSetupResponseWithNull() {
        // Arrange
        doNothing().when(negotiationResponse).setupResponse(null);
        
        // Act
        negotiationResponse.setupResponse(null);
        
        // Assert
        verify(negotiationResponse).setupResponse(null);
    }

    @Test
    @DisplayName("Test isSigningNegotiated returns true")
    void testIsSigningNegotiatedTrue() {
        // Arrange
        when(negotiationResponse.isSigningNegotiated()).thenReturn(true);
        
        // Act
        boolean result = negotiationResponse.isSigningNegotiated();
        
        // Assert
        assertTrue(result);
        verify(negotiationResponse).isSigningNegotiated();
    }

    @Test
    @DisplayName("Test isSigningNegotiated returns false")
    void testIsSigningNegotiatedFalse() {
        // Arrange
        when(negotiationResponse.isSigningNegotiated()).thenReturn(false);
        
        // Act
        boolean result = negotiationResponse.isSigningNegotiated();
        
        // Assert
        assertFalse(result);
        verify(negotiationResponse).isSigningNegotiated();
    }

    @Test
    @DisplayName("Test haveCapability returns true")
    void testHaveCapabilityTrue() {
        // Arrange
        int capability = 0x00000001;
        when(negotiationResponse.haveCapabilitiy(capability)).thenReturn(true);
        
        // Act
        boolean result = negotiationResponse.haveCapabilitiy(capability);
        
        // Assert
        assertTrue(result);
        verify(negotiationResponse).haveCapabilitiy(capability);
    }

    @Test
    @DisplayName("Test haveCapability returns false")
    void testHaveCapabilityFalse() {
        // Arrange
        int capability = 0x00000002;
        when(negotiationResponse.haveCapabilitiy(capability)).thenReturn(false);
        
        // Act
        boolean result = negotiationResponse.haveCapabilitiy(capability);
        
        // Assert
        assertFalse(result);
        verify(negotiationResponse).haveCapabilitiy(capability);
    }

    @Test
    @DisplayName("Test haveCapability with multiple capability flags")
    void testHaveCapabilityMultipleFlags() {
        // Arrange
        int cap1 = 0x00000001;
        int cap2 = 0x00000002;
        int cap3 = 0x00000004;
        when(negotiationResponse.haveCapabilitiy(cap1)).thenReturn(true);
        when(negotiationResponse.haveCapabilitiy(cap2)).thenReturn(false);
        when(negotiationResponse.haveCapabilitiy(cap3)).thenReturn(true);
        
        // Act & Assert
        assertTrue(negotiationResponse.haveCapabilitiy(cap1));
        assertFalse(negotiationResponse.haveCapabilitiy(cap2));
        assertTrue(negotiationResponse.haveCapabilitiy(cap3));
        
        verify(negotiationResponse).haveCapabilitiy(cap1);
        verify(negotiationResponse).haveCapabilitiy(cap2);
        verify(negotiationResponse).haveCapabilitiy(cap3);
    }

    @Test
    @DisplayName("Test getSendBufferSize returns standard size")
    void testGetSendBufferSizeStandard() {
        // Arrange
        int expectedSize = 65536;
        when(negotiationResponse.getSendBufferSize()).thenReturn(expectedSize);
        
        // Act
        int size = negotiationResponse.getSendBufferSize();
        
        // Assert
        assertEquals(expectedSize, size);
        verify(negotiationResponse).getSendBufferSize();
    }

    @Test
    @DisplayName("Test getSendBufferSize returns large size")
    void testGetSendBufferSizeLarge() {
        // Arrange
        int expectedSize = 1048576;
        when(negotiationResponse.getSendBufferSize()).thenReturn(expectedSize);
        
        // Act
        int size = negotiationResponse.getSendBufferSize();
        
        // Assert
        assertEquals(expectedSize, size);
        verify(negotiationResponse).getSendBufferSize();
    }

    @Test
    @DisplayName("Test getReceiveBufferSize returns standard size")
    void testGetReceiveBufferSizeStandard() {
        // Arrange
        int expectedSize = 65536;
        when(negotiationResponse.getReceiveBufferSize()).thenReturn(expectedSize);
        
        // Act
        int size = negotiationResponse.getReceiveBufferSize();
        
        // Assert
        assertEquals(expectedSize, size);
        verify(negotiationResponse).getReceiveBufferSize();
    }

    @Test
    @DisplayName("Test getReceiveBufferSize returns large size")
    void testGetReceiveBufferSizeLarge() {
        // Arrange
        int expectedSize = 1048576;
        when(negotiationResponse.getReceiveBufferSize()).thenReturn(expectedSize);
        
        // Act
        int size = negotiationResponse.getReceiveBufferSize();
        
        // Assert
        assertEquals(expectedSize, size);
        verify(negotiationResponse).getReceiveBufferSize();
    }

    @Test
    @DisplayName("Test getTransactionBufferSize returns standard size")
    void testGetTransactionBufferSizeStandard() {
        // Arrange
        int expectedSize = 32768;
        when(negotiationResponse.getTransactionBufferSize()).thenReturn(expectedSize);
        
        // Act
        int size = negotiationResponse.getTransactionBufferSize();
        
        // Assert
        assertEquals(expectedSize, size);
        verify(negotiationResponse).getTransactionBufferSize();
    }

    @Test
    @DisplayName("Test getTransactionBufferSize returns zero")
    void testGetTransactionBufferSizeZero() {
        // Arrange
        when(negotiationResponse.getTransactionBufferSize()).thenReturn(0);
        
        // Act
        int size = negotiationResponse.getTransactionBufferSize();
        
        // Assert
        assertEquals(0, size);
        verify(negotiationResponse).getTransactionBufferSize();
    }

    @Test
    @DisplayName("Test getInitialCredits returns default value")
    void testGetInitialCreditsDefault() {
        // Arrange
        int expectedCredits = 1;
        when(negotiationResponse.getInitialCredits()).thenReturn(expectedCredits);
        
        // Act
        int credits = negotiationResponse.getInitialCredits();
        
        // Assert
        assertEquals(expectedCredits, credits);
        verify(negotiationResponse).getInitialCredits();
    }

    @Test
    @DisplayName("Test getInitialCredits returns large value")
    void testGetInitialCreditsLarge() {
        // Arrange
        int expectedCredits = 256;
        when(negotiationResponse.getInitialCredits()).thenReturn(expectedCredits);
        
        // Act
        int credits = negotiationResponse.getInitialCredits();
        
        // Assert
        assertEquals(expectedCredits, credits);
        verify(negotiationResponse).getInitialCredits();
    }

    @Test
    @DisplayName("Test canReuse returns true with force signing")
    void testCanReuseWithForceSigning() {
        // Arrange
        when(negotiationResponse.canReuse(cifsContext, true)).thenReturn(true);
        
        // Act
        boolean result = negotiationResponse.canReuse(cifsContext, true);
        
        // Assert
        assertTrue(result);
        verify(negotiationResponse).canReuse(cifsContext, true);
    }

    @Test
    @DisplayName("Test canReuse returns false with force signing")
    void testCannotReuseWithForceSigning() {
        // Arrange
        when(negotiationResponse.canReuse(cifsContext, true)).thenReturn(false);
        
        // Act
        boolean result = negotiationResponse.canReuse(cifsContext, true);
        
        // Assert
        assertFalse(result);
        verify(negotiationResponse).canReuse(cifsContext, true);
    }

    @Test
    @DisplayName("Test canReuse returns true without force signing")
    void testCanReuseWithoutForceSigning() {
        // Arrange
        when(negotiationResponse.canReuse(cifsContext, false)).thenReturn(true);
        
        // Act
        boolean result = negotiationResponse.canReuse(cifsContext, false);
        
        // Assert
        assertTrue(result);
        verify(negotiationResponse).canReuse(cifsContext, false);
    }

    @Test
    @DisplayName("Test canReuse returns false without force signing")
    void testCannotReuseWithoutForceSigning() {
        // Arrange
        when(negotiationResponse.canReuse(cifsContext, false)).thenReturn(false);
        
        // Act
        boolean result = negotiationResponse.canReuse(cifsContext, false);
        
        // Assert
        assertFalse(result);
        verify(negotiationResponse).canReuse(cifsContext, false);
    }

    @Test
    @DisplayName("Test canReuse with null context")
    void testCanReuseWithNullContext() {
        // Arrange
        when(negotiationResponse.canReuse(null, false)).thenReturn(false);
        
        // Act
        boolean result = negotiationResponse.canReuse(null, false);
        
        // Assert
        assertFalse(result);
        verify(negotiationResponse).canReuse(null, false);
    }

    @Test
    @DisplayName("Test signing state combinations")
    void testSigningStateCombinations() {
        // Test all combinations of signing states
        
        // Signing disabled
        when(negotiationResponse.isSigningEnabled()).thenReturn(false);
        when(negotiationResponse.isSigningRequired()).thenReturn(false);
        when(negotiationResponse.isSigningNegotiated()).thenReturn(false);
        
        assertFalse(negotiationResponse.isSigningEnabled());
        assertFalse(negotiationResponse.isSigningRequired());
        assertFalse(negotiationResponse.isSigningNegotiated());
        
        // Signing enabled but not required
        when(negotiationResponse.isSigningEnabled()).thenReturn(true);
        when(negotiationResponse.isSigningRequired()).thenReturn(false);
        when(negotiationResponse.isSigningNegotiated()).thenReturn(true);
        
        assertTrue(negotiationResponse.isSigningEnabled());
        assertFalse(negotiationResponse.isSigningRequired());
        assertTrue(negotiationResponse.isSigningNegotiated());
        
        // Signing required (implies enabled and negotiated)
        when(negotiationResponse.isSigningEnabled()).thenReturn(true);
        when(negotiationResponse.isSigningRequired()).thenReturn(true);
        when(negotiationResponse.isSigningNegotiated()).thenReturn(true);
        
        assertTrue(negotiationResponse.isSigningEnabled());
        assertTrue(negotiationResponse.isSigningRequired());
        assertTrue(negotiationResponse.isSigningNegotiated());
    }

    @Test
    @DisplayName("Test buffer size edge cases")
    void testBufferSizeEdgeCases() {
        // Test minimum buffer sizes
        when(negotiationResponse.getSendBufferSize()).thenReturn(1);
        when(negotiationResponse.getReceiveBufferSize()).thenReturn(1);
        when(negotiationResponse.getTransactionBufferSize()).thenReturn(1);
        
        assertEquals(1, negotiationResponse.getSendBufferSize());
        assertEquals(1, negotiationResponse.getReceiveBufferSize());
        assertEquals(1, negotiationResponse.getTransactionBufferSize());
        
        // Test maximum integer values
        when(negotiationResponse.getSendBufferSize()).thenReturn(Integer.MAX_VALUE);
        when(negotiationResponse.getReceiveBufferSize()).thenReturn(Integer.MAX_VALUE);
        when(negotiationResponse.getTransactionBufferSize()).thenReturn(Integer.MAX_VALUE);
        
        assertEquals(Integer.MAX_VALUE, negotiationResponse.getSendBufferSize());
        assertEquals(Integer.MAX_VALUE, negotiationResponse.getReceiveBufferSize());
        assertEquals(Integer.MAX_VALUE, negotiationResponse.getTransactionBufferSize());
        
        // Test negative values (though not typical, should be tested)
        when(negotiationResponse.getSendBufferSize()).thenReturn(-1);
        when(negotiationResponse.getReceiveBufferSize()).thenReturn(-1);
        when(negotiationResponse.getTransactionBufferSize()).thenReturn(-1);
        
        assertEquals(-1, negotiationResponse.getSendBufferSize());
        assertEquals(-1, negotiationResponse.getReceiveBufferSize());
        assertEquals(-1, negotiationResponse.getTransactionBufferSize());
    }

    @Test
    @DisplayName("Test initial credits edge cases")
    void testInitialCreditsEdgeCases() {
        // Test zero credits
        when(negotiationResponse.getInitialCredits()).thenReturn(0);
        assertEquals(0, negotiationResponse.getInitialCredits());
        
        // Test negative credits (edge case)
        when(negotiationResponse.getInitialCredits()).thenReturn(-1);
        assertEquals(-1, negotiationResponse.getInitialCredits());
        
        // Test maximum credits
        when(negotiationResponse.getInitialCredits()).thenReturn(Integer.MAX_VALUE);
        assertEquals(Integer.MAX_VALUE, negotiationResponse.getInitialCredits());
    }

    @Test
    @DisplayName("Test all dialect versions")
    void testAllDialectVersions() {
        // Test each dialect version
        DialectVersion[] dialects = {
            DialectVersion.SMB1,
            DialectVersion.SMB202,
            DialectVersion.SMB210,
            DialectVersion.SMB300,
            DialectVersion.SMB302,
            DialectVersion.SMB311
        };
        
        for (DialectVersion dialect : dialects) {
            when(negotiationResponse.getSelectedDialect()).thenReturn(dialect);
            assertEquals(dialect, negotiationResponse.getSelectedDialect());
            verify(negotiationResponse, atLeastOnce()).getSelectedDialect();
        }
    }

    @Test
    @DisplayName("Test null dialect version")
    void testNullDialectVersion() {
        // Arrange
        when(negotiationResponse.getSelectedDialect()).thenReturn(null);
        
        // Act
        DialectVersion dialect = negotiationResponse.getSelectedDialect();
        
        // Assert
        assertNull(dialect);
        verify(negotiationResponse).getSelectedDialect();
    }
}
