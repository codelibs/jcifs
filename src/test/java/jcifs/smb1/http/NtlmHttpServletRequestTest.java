package jcifs.smb1.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.Principal;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class NtlmHttpServletRequestTest {

    @Test
    @DisplayName("constructor stores principal and delegates properly")
    void testHappyPath(@Mock HttpServletRequest mockRequest, @Mock Principal mockPrincipal) {
        when(mockPrincipal.getName()).thenReturn("user1");
        NtlmHttpServletRequest request = new NtlmHttpServletRequest(mockRequest, mockPrincipal);
        assertEquals("user1", request.getRemoteUser());
        assertSame(mockPrincipal, request.getUserPrincipal());
        assertEquals("NTLM", request.getAuthType());
        verify(mockPrincipal, times(1)).getName();
    }

    @ParameterizedTest
    @ValueSource(strings = { "", "   ", "unknown" })
    @DisplayName("supports multiple principal name variants")
    void testPrincipalNameVariants(String name, @Mock HttpServletRequest mockRequest, @Mock Principal mockPrincipal) {
        when(mockPrincipal.getName()).thenReturn(name);
        NtlmHttpServletRequest request = new NtlmHttpServletRequest(mockRequest, mockPrincipal);
        assertEquals(name, request.getRemoteUser());
        verify(mockPrincipal, times(1)).getName();
    }

    @Test
    @DisplayName("constructor accepts null principal")
    void testConstructorWithNullPrincipal(@Mock HttpServletRequest mockRequest) {
        // Constructor accepts null principal without throwing exception
        NtlmHttpServletRequest request = new NtlmHttpServletRequest(mockRequest, null);

        // getRemoteUser() will throw NPE when trying to call getName() on null principal
        assertThrows(NullPointerException.class, () -> request.getRemoteUser());
        assertNull(request.getUserPrincipal());
        assertEquals("NTLM", request.getAuthType());
    }

    @Test
    @DisplayName("constructor rejects null HttpServletRequest")
    void testConstructorWithNullHttpRequest(@Mock Principal mockPrincipal) {
        // HttpServletRequestWrapper throws IllegalArgumentException for null request
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> new NtlmHttpServletRequest(null, mockPrincipal));
        assertEquals("Request cannot be null", ex.getMessage());
    }

    @Test
    @DisplayName("auth type is always NTLM")
    void testAuthTypeConstant(@Mock HttpServletRequest mockRequest, @Mock Principal mockPrincipal) {
        // No need to stub getName() since we're not calling getRemoteUser()
        NtlmHttpServletRequest request = new NtlmHttpServletRequest(mockRequest, mockPrincipal);
        assertEquals("NTLM", request.getAuthType());
        // Verify it returns the same value on multiple calls
        assertEquals("NTLM", request.getAuthType());
    }
}
