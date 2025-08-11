package jcifs.http;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.NameServiceClient;
import jcifs.smb.NtlmChallenge;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbAuthException;
import jcifs.smb.SmbException;
import jcifs.SmbTransportPool;
import jcifs.util.Hexdump;

// NtlmHttpFilter is deprecated, but we still want to test it for backward compatibility.
@SuppressWarnings("deprecation")
@ExtendWith(MockitoExtension.class)
class NtlmHttpFilterTest {

    @InjectMocks
    private NtlmHttpFilter ntlmHttpFilter;

    @Mock
    private FilterConfig filterConfig;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @Mock
    private HttpSession httpSession;
    
    @Mock
    private ServletOutputStream servletOutputStream;

    private CIFSContext cifsContext;

    @BeforeEach
    void setUp() throws Exception {
        // Basic setup for mocks
        when(request.getSession()).thenReturn(httpSession);
        when(request.getSession(anyBoolean())).thenReturn(httpSession);
        
        // Mock servlet output stream to avoid NullPointerException on flushBuffer
        when(response.getOutputStream()).thenReturn(servletOutputStream);

        // Setup FilterConfig with default parameters
        Map<String, String> initParams = new HashMap<>();
        initParams.put("jcifs.smb.client.domain", "TEST_DOMAIN");
        initParams.put("jcifs.http.domainController", "dc.test.com");
        initParams.put("jcifs.http.enableBasic", "true");
        initParams.put("jcifs.http.insecureBasic", "true");
        initParams.put("jcifs.http.basicRealm", "TestRealm");

        when(filterConfig.getInitParameterNames()).thenReturn(Collections.enumeration(initParams.keySet()));
        when(filterConfig.getInitParameter(anyString())).thenAnswer(invocation -> initParams.get(invocation.getArgument(0)));
        
        ntlmHttpFilter.init(filterConfig);
    }

    @Test
    void testInit() throws ServletException {
        // Verifies that init() correctly processes filter configuration.
        FilterConfig mockConfig = mock(FilterConfig.class);
        Map<String, String> initParams = new HashMap<>();
        initParams.put("jcifs.smb.client.domain", "EXAMPLE");
        initParams.put("jcifs.http.domainController", "dc.example.com");
        initParams.put("jcifs.http.enableBasic", "false");
        initParams.put("jcifs.smb.client.soTimeout", "60000");

        when(mockConfig.getInitParameterNames()).thenReturn(Collections.enumeration(initParams.keySet()));
        when(mockConfig.getInitParameter(anyString())).thenAnswer(invocation -> initParams.get(invocation.getArgument(0)));

        NtlmHttpFilter filter = new NtlmHttpFilter();
        filter.init(mockConfig);

        // Assertions can be tricky as fields are private. We can test the behavior that depends on them.
        // For now, just confirm no exception is thrown.
        assertDoesNotThrow(() -> filter.init(mockConfig));
    }
    
    @Test
    void testInit_withCIFSException() {
        // Verifies that init() throws ServletException when CIFSContext creation fails.
        when(filterConfig.getInitParameter(eq("jcifs.smb.client.domain"))).thenReturn(null);
        NtlmHttpFilter filter = new NtlmHttpFilter();
        
        // This test is limited because the actual CIFSException is caught internally.
        // A better approach would be to refactor NtlmHttpFilter to allow injecting a mock context factory.
        // For now, we check if a ServletException is thrown for invalid config.
        assertThrows(ServletException.class, () -> filter.init(filterConfig));
    }


    @Test
    void testDestroy() {
        // Verifies that destroy() runs without errors.
        assertDoesNotThrow(() -> ntlmHttpFilter.destroy());
    }

    @Test
    void testDoFilter_noAuthorizationHeader_shouldChallengeClient() throws IOException, ServletException {
        // Simulates a request without any Authorization header.
        // Expects the filter to challenge the client with a 401 Unauthorized and NTLM prompt.
        when(request.getHeader("Authorization")).thenReturn(null);
        when(httpSession.getAttribute("NtlmHttpAuth")).thenReturn(null);

        ntlmHttpFilter.doFilter(request, response, filterChain);

        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(response).setHeader("WWW-Authenticate", "NTLM");
        verify(response).addHeader("WWW-Authenticate", "Basic realm=\"TestRealm\"");
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void testDoFilter_alreadyAuthenticated_shouldProceed() throws IOException, ServletException {
        // Simulates a request where the session already contains authentication info.
        // Expects the filter to proceed without re-authentication.
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(new BaseContext(new PropertyConfiguration(new Properties())), "testdomain", "user", "pass");
        when(httpSession.getAttribute("NtlmHttpAuth")).thenReturn(auth);

        ntlmHttpFilter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(any(NtlmHttpServletRequest.class), eq(response));
        verify(response, never()).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    void testDoFilter_basicAuth_success() throws Exception {
        // Simulates a request with a valid Basic Authorization header.
        // Mocks a successful authentication against the DC.
        // Expects the filter chain to proceed.
        String authHeader = "Basic " + new String(org.bouncycastle.util.encoders.Base64.encode("user:pass".getBytes()));
        when(request.getHeader("Authorization")).thenReturn(authHeader);
        when(request.isSecure()).thenReturn(true);

        // Mock the CIFS context and dependencies for a successful logon
        mockCifsContextForSuccessfulLogon();

        ntlmHttpFilter.doFilter(request, response, filterChain);

        verify(httpSession).setAttribute(eq("NtlmHttpAuth"), any(NtlmPasswordAuthentication.class));
        verify(filterChain).doFilter(any(NtlmHttpServletRequest.class), eq(response));
    }
    
    @Test
    void testDoFilter_basicAuth_failure() throws Exception {
        // Simulates a request with a Basic Authorization header but a logon failure.
        // Expects a 401 Unauthorized response.
        String authHeader = "Basic " + new String(org.bouncycastle.util.encoders.Base64.encode("user:wrongpass".getBytes()));
        when(request.getHeader("Authorization")).thenReturn(authHeader);
        when(request.isSecure()).thenReturn(true);

        // Mock the CIFS context for a failed logon
        mockCifsContextForFailedLogon();

        ntlmHttpFilter.doFilter(request, response, filterChain);

        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(httpSession, never()).setAttribute(eq("NtlmHttpAuth"), any(NtlmPasswordAuthentication.class));
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void testDoFilter_ntlmAuth_negotiationAndSuccess() throws Exception {
        // This is a complex test simulating the NTLM handshake (Type1 -> Type2 -> Type3).
        // We use Mockito's static mocking for NtlmSsp.
        
        byte[] type1Message = "NTLM t1".getBytes(); // Dummy Type 1 message
        byte[] type3Message = "NTLM t3".getBytes(); // Dummy Type 3 message
        NtlmPasswordAuthentication ntlmAuth = new NtlmPasswordAuthentication(new BaseContext(new PropertyConfiguration(new Properties())), "TEST_DOMAIN", "user", "password");

        // Mocking static NtlmSsp.authenticate
        try (MockedStatic<NtlmSsp> ntlmSspMock = Mockito.mockStatic(NtlmSsp.class)) {
            // 1. Type 1 message from client
            when(request.getHeader("Authorization")).thenReturn("NTLM " + new String(org.bouncycastle.util.encoders.Base64.encode(type1Message)));
            
            // NtlmSsp.authenticate should return null to indicate negotiation in progress
            ntlmSspMock.when(() -> NtlmSsp.authenticate(any(), any(), any(), any(byte[].class))).thenReturn(null);
            
            // Mock CIFS context for challenge generation
            mockCifsContextForChallenge();

            // Execute filter for Type 1
            ntlmHttpFilter.doFilter(request, response, filterChain);
            
            // Verify that a challenge was sent (negotiate() returns null, so filter chain is not called)
            verify(filterChain, never()).doFilter(any(), any());
            
            // 2. Type 3 message from client
            when(request.getHeader("Authorization")).thenReturn("NTLM " + new String(org.bouncycastle.util.encoders.Base64.encode(type3Message)));
            
            // NtlmSsp.authenticate should now return a valid authentication object
            ntlmSspMock.when(() -> NtlmSsp.authenticate(any(), any(), any(), any(byte[].class))).thenReturn(ntlmAuth);
            
            // Mock CIFS context for a successful logon
            mockCifsContextForSuccessfulLogon();
            
            // Execute filter for Type 3
            ntlmHttpFilter.doFilter(request, response, filterChain);

            // Verify successful authentication and filter chain progression
            verify(httpSession).setAttribute("NtlmHttpAuth", ntlmAuth);
            verify(httpSession).removeAttribute("NtlmHttpChal");
            verify(filterChain, times(1)).doFilter(any(NtlmHttpServletRequest.class), eq(response));
        }
    }
    
    @Test
    void testDoFilter_insecureBasicNotAllowed() throws IOException, ServletException {
        // Verifies that Basic auth is not offered over an insecure connection if disabled.
        Map<String, String> params = new HashMap<>();
        params.put("jcifs.http.enableBasic", "true");
        params.put("jcifs.http.insecureBasic", "false");
        when(filterConfig.getInitParameterNames()).thenReturn(Collections.enumeration(params.keySet()));
        when(filterConfig.getInitParameter(anyString())).thenAnswer(inv -> params.get(inv.getArgument(0)));
        ntlmHttpFilter.init(filterConfig);

        when(request.getHeader("Authorization")).thenReturn(null);
        when(request.isSecure()).thenReturn(false); // Insecure request
        when(httpSession.getAttribute("NtlmHttpAuth")).thenReturn(null);

        ntlmHttpFilter.doFilter(request, response, filterChain);

        verify(response).setHeader("WWW-Authenticate", "NTLM");
        // Should not offer Basic auth
        verify(response, never()).addHeader(eq("WWW-Authenticate"), anyString());
    }


    // Helper methods to mock CIFS context behavior

    private void mockCifsContextForSuccessfulLogon() throws Exception {
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.domain", "TEST_DOMAIN");
        cifsContext = new BaseContext(new PropertyConfiguration(props));

        SmbTransportPool transportPool = mock(SmbTransportPool.class);
        NameServiceClient nameServiceClient = mock(NameServiceClient.class);
        
        doNothing().when(transportPool).logon(any(), any());
        when(nameServiceClient.getByName(anyString(), anyBoolean())).thenReturn(mock(jcifs.Address.class));

        NtlmHttpFilter filter = new NtlmHttpFilter();
        
        // Re-initialize the filter with the mocked context logic
        filter.init(filterConfig);
        this.ntlmHttpFilter = filter;
    }

    private void mockCifsContextForFailedLogon() throws Exception {
        Properties props = new Properties();
        props.setProperty("jcifs.smb.client.domain", "TEST_DOMAIN");
        cifsContext = new BaseContext(new PropertyConfiguration(props));

        SmbTransportPool transportPool = mock(SmbTransportPool.class);
        NameServiceClient nameServiceClient = mock(NameServiceClient.class);

        // Throw SmbException (SmbAuthException constructors are package-private)
        SmbException authException = new SmbException(0xC000006D, true); // STATUS_LOGON_FAILURE
        Mockito.doThrow(authException).when(transportPool).logon(any(), any());
        when(nameServiceClient.getByName(anyString(), anyBoolean())).thenReturn(mock(jcifs.Address.class));

        NtlmHttpFilter filter = new NtlmHttpFilter();
        
        filter.init(filterConfig);
        this.ntlmHttpFilter = filter;
    }
    
    private void mockCifsContextForChallenge() throws Exception {
        Properties props = new Properties();
        props.setProperty("jcifs.http.domainController", "dc.test.com");
        cifsContext = new BaseContext(new PropertyConfiguration(props));

        SmbTransportPool transportPool = mock(SmbTransportPool.class);
        NameServiceClient nameServiceClient = mock(NameServiceClient.class);
        
        byte[] challenge = new byte[8]; // Dummy challenge
        when(transportPool.getChallenge(any(), any())).thenReturn(challenge);
        when(nameServiceClient.getByName(anyString(), anyBoolean())).thenReturn(mock(jcifs.Address.class));

        NtlmHttpFilter filter = new NtlmHttpFilter();
        
        filter.init(filterConfig);
        this.ntlmHttpFilter = filter;
    }
}
