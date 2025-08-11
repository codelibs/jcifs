package jcifs.smb1.http;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.ParameterizedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;

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
    @ValueSource(strings = {"", "   ", "unknown"})
    @DisplayName("supports multiple principal name variants")
    void testPrincipalNameVariants(String name, @Mock HttpServletRequest mockRequest, @Mock Principal mockPrincipal) {
        when(mockPrincipal.getName()).thenReturn(name);
        NtlmHttpServletRequest request = new NtlmHttpServletRequest(mockRequest, mockPrincipal);
        assertEquals(name, request.getRemoteUser());
        verify(mockPrincipal, times(1)).getName();
    }

    @Test
    @DisplayName("constructor rejects null principal")
    void testConstructorWithNullPrincipal(@Mock HttpServletRequest mockRequest) {
        NullPointerException npe = assertThrows(NullPointerException.class, () ->
                new NtlmHttpServletRequest(mockRequest, null));
        assertNotNull(npe.getMessage());
    }

    @Test
    @DisplayName("constructor rejects null HttpServletRequest")
    void testConstructorWithNullHttpRequest(@Mock Principal mockPrincipal) {
        assertThrows(NullPointerException.class, () ->
                new NtlmHttpServletRequest(null, mockPrincipal));
    }

    @Test
    @DisplayName("auth type is always NTLM")
    void testAuthTypeConstant(@Mock HttpServletRequest mockRequest, @Mock Principal mockPrincipal) {
        when(mockPrincipal.getName()).thenReturn("any");
        NtlmHttpServletRequest request = new NtlmHttpServletRequest(mockRequest, mockPrincipal);
        assertEquals("NTLM", request.getAuthType());
        assertEquals("NTLM", request.getAuthType());
    }
}
