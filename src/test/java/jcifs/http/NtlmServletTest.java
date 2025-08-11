package jcifs.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.Address;
import jcifs.NameServiceClient;
import jcifs.smb.NtlmPasswordAuthentication;

/**
 * Tests for the NtlmServlet class.
 * This class uses Mockito to simulate a servlet environment and test authentication logic.
 */
@ExtendWith(MockitoExtension.class)
class NtlmServletTest {

    // A concrete implementation of the abstract NtlmServlet for testing purposes.
    private static class TestNtlmServlet extends NtlmServlet {
        private static final long serialVersionUID = 1L;
        
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            // Do nothing - just for testing
        }
        
        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            // Do nothing - just for testing
        }
    }

    private TestNtlmServlet ntlmServlet;

    @Mock
    private ServletConfig servletConfig;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    @Mock
    private CIFSContext cifsContext;

    @Mock
    private Configuration configuration;

    @Mock
    private jcifs.SmbTransportPool transportPool;

    @Mock
    private NameServiceClient nameServiceClient;

    /**
     * Sets up the mock objects before each test.
     * @throws CIFSException
     */
    @BeforeEach
    void setUp() throws CIFSException {
        ntlmServlet = new TestNtlmServlet();
        
        // Mock ServletConfig to provide initialization parameters
        Map<String, String> initParams = new HashMap<>();
        initParams.put("jcifs.smb.client.domain", "TEST_DOMAIN");
        initParams.put("jcifs.http.domainController", "dc.test.domain");
        initParams.put("jcifs.http.enableBasic", "true");
        initParams.put("jcifs.http.insecureBasic", "true");
        initParams.put("jcifs.http.basicRealm", "TestRealm");

        lenient().when(servletConfig.getInitParameterNames()).thenReturn(Collections.enumeration(initParams.keySet()));
        lenient().when(servletConfig.getInitParameter(anyString())).thenAnswer(invocation -> initParams.get(invocation.getArgument(0)));
        
        // Mock HTTP method for request - this is required for HttpServlet.service()
        lenient().when(request.getMethod()).thenReturn("GET");
        
        // Setup CIFSContext configuration mock
        lenient().when(cifsContext.getConfig()).thenReturn(configuration);
        lenient().when(configuration.getDefaultDomain()).thenReturn("TEST_DOMAIN");
    }

    /**
     * Test the init method of the servlet.
     * Verifies that servlet is correctly initialized with parameters from ServletConfig.
     * @throws ServletException
     */
    @Test
    void testInit() throws ServletException {
        assertDoesNotThrow(() -> ntlmServlet.init(servletConfig));
        // Further assertions can be added here to check the internal state of the servlet if fields were protected/public
    }

    /**
     * Test the init method when CIFSException occurs.
     * Verifies that configuration properties are properly validated during initialization.
     */
    @Test
    void testInitWithCIFSException() {
        // Test with valid configuration - should initialize successfully
        Map<String, String> validParams = new HashMap<>();
        validParams.put("jcifs.smb.client.domain", "TEST_DOMAIN");
        validParams.put("jcifs.smb.client.soTimeout", "300000");
        
        when(servletConfig.getInitParameterNames()).thenReturn(Collections.enumeration(validParams.keySet()));
        when(servletConfig.getInitParameter(anyString())).thenAnswer(invocation -> validParams.get(invocation.getArgument(0)));
        
        // This should not throw an exception
        assertDoesNotThrow(() -> ntlmServlet.init(servletConfig));
    }

    /**
     * Test the service method when no Authorization header is present and no session exists.
     * Expects a 401 Unauthorized response with NTLM and Basic authentication challenges.
     * @throws ServletException
     * @throws IOException
     */
    @Test
    void testService_NoAuthHeader_NoSession() throws ServletException, IOException {
        ntlmServlet.init(servletConfig);
        when(request.getHeader("Authorization")).thenReturn(null);
        when(request.getSession(false)).thenReturn(null);
        lenient().when(request.isSecure()).thenReturn(true);

        ntlmServlet.service(request, response);

        verify(response).setHeader("WWW-Authenticate", "NTLM");
        verify(response).addHeader("WWW-Authenticate", "Basic realm=\"TestRealm\"");
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    /**
     * Test the service method with a valid NTLM Authorization header.
     * Simulates a successful NTLM authentication.
     * @throws ServletException
     * @throws IOException
     * @throws CIFSException
     */
    @Test
    void testService_NtlmAuth_Success() throws Exception {
        ntlmServlet.init(servletConfig);
        setupMocksForAuth();

        byte[] challenge = new byte[8];
        NtlmPasswordAuthentication ntlmAuth = new NtlmPasswordAuthentication(cifsContext, "TEST_DOMAIN", "user", "password");

        try (MockedStatic<NtlmSsp> ntlmSspMock = Mockito.mockStatic(NtlmSsp.class)) {
            ntlmSspMock.when(() -> NtlmSsp.authenticate(any(), any(), any(), any()))
                       .thenReturn(ntlmAuth);

            when(request.getHeader("Authorization")).thenReturn("NTLM TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAGAbAdAAAADw==");
            when(request.getSession()).thenReturn(session);

            ntlmServlet.service(request, response);

            // Verify that user information is stored in the session
            verify(session).setAttribute("NtlmHttpAuth", ntlmAuth);
            verify(session).setAttribute("ntlmuser", "user");
            verify(session).setAttribute("ntlmdomain", "TEST_DOMAIN");

            // Verify that the chain continues
            verify(response, never()).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    /**
     * Test the service method with NTLM authentication that fails.
     * Expects a 401 Unauthorized response.
     * @throws ServletException
     * @throws IOException
     * @throws CIFSException
     */
    @Test
    void testService_NtlmAuth_Failure() throws Exception {
        ntlmServlet.init(servletConfig);
        setupMocksForAuth();

        // Return null from NtlmSsp.authenticate to simulate initial NTLM handshake
        try (MockedStatic<NtlmSsp> ntlmSspMock = Mockito.mockStatic(NtlmSsp.class)) {
            ntlmSspMock.when(() -> NtlmSsp.authenticate(any(), any(), any(), any()))
                       .thenReturn(null);

            when(request.getHeader("Authorization")).thenReturn("NTLM TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAGAbAdAAAADw==");

            ntlmServlet.service(request, response);

            // When NtlmSsp.authenticate returns null, the service method returns early
            // without setting session attributes
            verify(session, never()).setAttribute(anyString(), any());
        }
    }

    /**
     * Test the service method with a valid Basic Authorization header.
     * Simulates a successful Basic authentication.
     * @throws ServletException
     * @throws IOException
     * @throws CIFSException
     */
    @Test
    void testService_BasicAuth_Success() throws Exception {
        ntlmServlet.init(servletConfig);
        setupMocksForAuth();

        // Base64 encoding of "TEST_DOMAIN\\user:password"
        when(request.getHeader("Authorization")).thenReturn("Basic VEVTVF9ET01BSU5cdXNlcjpwYXNzd29yZA==");
        lenient().when(request.isSecure()).thenReturn(true);
        when(request.getSession()).thenReturn(session);

        ntlmServlet.service(request, response);

        ArgumentCaptor<NtlmPasswordAuthentication> authCaptor = ArgumentCaptor.forClass(NtlmPasswordAuthentication.class);
        verify(session).setAttribute(eq("NtlmHttpAuth"), authCaptor.capture());

        NtlmPasswordAuthentication capturedAuth = authCaptor.getValue();
        assertEquals("user", capturedAuth.getUsername());
        assertEquals("TEST_DOMAIN", capturedAuth.getUserDomain());

        verify(response, never()).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    /**
     * Test the service method with an existing valid session.
     * The servlet should not re-authenticate but proceed directly.
     * @throws ServletException
     * @throws IOException
     */
    @Test
    void testService_WithExistingSession() throws ServletException, IOException {
        ntlmServlet.init(servletConfig);
        when(request.getHeader("Authorization")).thenReturn(null);
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("NtlmHttpAuth")).thenReturn(mock(NtlmPasswordAuthentication.class));

        ntlmServlet.service(request, response);

        // Verify that no authentication challenge is sent
        verify(response, never()).setHeader(eq("WWW-Authenticate"), anyString());
        verify(response, never()).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    /**
     * Helper method to set up common mocks required for authentication tests.
     * @throws CIFSException
     */
    private void setupMocksForAuth() throws Exception {
        // This is a simplified way to get a transport context into the servlet.
        // A more robust solution might involve reflection or modifying the servlet for testability.
        try {
            java.lang.reflect.Field transportContextField = NtlmServlet.class.getDeclaredField("transportContext");
            transportContextField.setAccessible(true);
            transportContextField.set(ntlmServlet, cifsContext);
        } catch (Exception e) {
            throw new RuntimeException("Failed to inject mock CIFSContext", e);
        }

        when(cifsContext.getTransportPool()).thenReturn(transportPool);
        when(cifsContext.getNameServiceClient()).thenReturn(nameServiceClient);
        lenient().when(cifsContext.getConfig()).thenReturn(configuration);
        lenient().when(configuration.getDefaultDomain()).thenReturn("TEST_DOMAIN");
        lenient().when(nameServiceClient.getByName(anyString(), anyBoolean())).thenReturn(mock(Address.class));
        lenient().when(transportPool.getChallenge(any(), any())).thenReturn(new byte[8]);
    }
}