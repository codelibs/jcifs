package jcifs.http;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.util.Collections;
import java.util.Vector;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import jcifs.CIFSContext;
import jcifs.context.SingletonContext;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbAuthException;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileInputStream;
import jcifs.smb1.util.LogStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for the {@link NetworkExplorer} class.
 */
@ExtendWith(MockitoExtension.class)
class NetworkExplorerTest {

    @InjectMocks
    private NetworkExplorer networkExplorer;

    @Mock
    private ServletConfig servletConfig;

    @Mock
    private ServletContext servletContext;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    @Mock
    private SmbFile smbFile;

    private StringWriter stringWriter;
    private PrintWriter printWriter;

    @BeforeEach
    void setUp() throws IOException, ServletException {
        // Suppress logging output
        LogStream.setInstance(new LogStream(new PrintStream(new ByteArrayOutputStream())));

        // Mock ServletOutputStream
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ServletOutputStream servletOutputStream = new ServletOutputStream() {
            @Override
            public void write(int b) throws IOException {
                baos.write(b);
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener writeListener) {
            }
        };

        stringWriter = new StringWriter();
        printWriter = new PrintWriter(stringWriter);

        when(response.getWriter()).thenReturn(printWriter);
        when(response.getOutputStream()).thenReturn(servletOutputStream);

        // Mock ServletConfig and ServletContext for init()
        when(servletConfig.getServletContext()).thenReturn(servletContext);
        when(servletConfig.getInitParameterNames()).thenReturn(Collections.emptyEnumeration());
        when(servletContext.getResourceAsStream(anyString()))
                .thenReturn(new ByteArrayInputStream("body {}".getBytes()));

        // Initialize the servlet
        networkExplorer = spy(new NetworkExplorer());
        networkExplorer.init(servletConfig);

        // Common mocking for request and response
        when(request.getSession(false)).thenReturn(session);
        when(request.getSession()).thenReturn(session);
    }

    /**
     * Test the init method of the NetworkExplorer servlet.
     */
    @Test
    void testInit() throws ServletException {
        // Create a new instance to test init specifically
        NetworkExplorer explorer = new NetworkExplorer();

        // Mock ServletConfig and ServletContext
        ServletConfig config = mock(ServletConfig.class);
        ServletContext context = mock(ServletContext.class);
        when(config.getServletContext()).thenReturn(context);
        when(context.getResourceAsStream(anyString()))
                .thenReturn(new ByteArrayInputStream("test_style".getBytes()));

        // Mock init parameters
        Vector<String> initParams = new Vector<>();
        initParams.add("jcifs.smb.client.domain");
        when(config.getInitParameterNames()).thenReturn(initParams.elements());
        when(config.getInitParameter("jcifs.smb.client.domain")).thenReturn("TEST_DOMAIN");

        // Call init
        explorer.init(config);

        // Verify that getInitParameter was called
        verify(config, atLeastOnce()).getInitParameter("jcifs.smb.client.domain");
        assertNotNull(explorer);
    }

    /**
     * Test doGet when no authentication is provided, expecting a 401 Unauthorized response.
     */
    @Test
    void testDoGet_Unauthorized_NoAuthHeader() throws IOException, ServletException {
        // Given: No Authorization header and no existing session authentication
        when(request.getHeader("Authorization")).thenReturn(null);
        when(session.getAttribute(anyString())).thenReturn(null);

        // When: doGet is called
        networkExplorer.doGet(request, response);

        // Then: Expect 401 Unauthorized and WWW-Authenticate headers
        verify(response).setHeader("WWW-Authenticate", "NTLM");
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(response).flushBuffer();
    }

    /**
     * Test doGet for a directory listing.
     */
    @Test
    void testDoGet_DirectoryListing_Success() throws IOException, ServletException {
        // Given: An authenticated session and a request for a directory
        NtlmPasswordAuthentication ntlm = new NtlmPasswordAuthentication(SingletonContext.getInstance(), "testdomain", "user", "pass");
        when(session.getAttribute(anyString())).thenReturn(ntlm);
        when(request.getPathInfo()).thenReturn("/workgroup/server/");

        // Mock listFiles to return a directory and a file
        SmbFile dir1 = mock(SmbFile.class);
        when(dir1.getName()).thenReturn("SubDir/");
        when(dir1.isDirectory()).thenReturn(true);

        SmbFile file1 = mock(SmbFile.class);
        when(file1.getName()).thenReturn("file.txt");
        when(file1.isDirectory()).thenReturn(false);
        when(file1.length()).thenReturn(1024L);
        when(file1.lastModified()).thenReturn(System.currentTimeMillis());

        SmbFile[] files = {dir1, file1};
        when(smbFile.listFiles()).thenReturn(files);
        when(smbFile.isDirectory()).thenReturn(true);

        // Mock doDirectory to verify it's called
        doNothing().when(networkExplorer).doDirectory(any(), any(), any());

        // When: doGet is called
        networkExplorer.doGet(request, response);

        // Then: Verify that doDirectory was called
        verify(networkExplorer).doDirectory(any(), any(), any());
    }

    /**
     * Test doGet for a file download.
     */
    @Test
    void testDoGet_FileDownload_Success() throws IOException, ServletException {
        // Given: An authenticated session and a request for a file
        NtlmPasswordAuthentication ntlm = new NtlmPasswordAuthentication(SingletonContext.getInstance(), "testdomain", "user", "pass");
        when(session.getAttribute(anyString())).thenReturn(ntlm);
        when(request.getPathInfo()).thenReturn("/workgroup/server/share/file.txt");

        // Mock SmbFile to represent a file
        when(smbFile.isDirectory()).thenReturn(false);
        when(smbFile.length()).thenReturn(12L);

        // Mock SmbFileInputStream
        byte[] fileContent = "Hello World!".getBytes();
        SmbFileInputStream smbInputStream = mock(SmbFileInputStream.class);
        when(smbFile.getInputStream()).thenReturn(smbInputStream);
        when(smbInputStream.read(any(byte[].class))).thenAnswer(invocation -> {
            byte[] buffer = invocation.getArgument(0);
            System.arraycopy(fileContent, 0, buffer, 0, fileContent.length);
            return fileContent.length;
        }).thenReturn(-1);

        // Mock doFile to verify it's called
        doNothing().when(networkExplorer).doFile(any(), any(), any());

        // When: doGet is called
        networkExplorer.doGet(request, response);

        // Then: Verify that doFile was called and headers are set correctly
        verify(networkExplorer).doFile(any(), any(), any());
        verify(response).setContentType(anyString());
        verify(response).setHeader("Content-Length", "12");
    }

    /**
     * Test doGet when an authentication failure would occur.
     * Since we can't directly test SmbAuthException due to its package-private constructor,
     * we'll test the behavior when authentication is not provided.
     */
    @Test
    void testDoGet_AuthFailure() throws IOException, ServletException {
        // Given: No authentication in session
        when(session.getAttribute(anyString())).thenReturn(null);
        when(request.getPathInfo()).thenReturn("/workgroup/server/share/");
        when(request.getHeader("Authorization")).thenReturn(null);

        // When: doGet is called without authentication
        networkExplorer.doGet(request, response);

        // Then: Verify 401 response is sent
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(response).flushBuffer();
    }

    /**
     * Test the doFile method directly.
     */
    @Test
    void testDoFile() throws IOException {
        // Given: A mock SmbFile and response objects
        String fileContent = "file content";
        long fileLength = fileContent.length();
        SmbFileInputStream smbInputStream = new SmbFileInputStream(smbFile);
        when(smbFile.length()).thenReturn(fileLength);
        when(smbFile.getInputStream()).thenReturn(smbInputStream);
        doReturn(new ByteArrayInputStream(fileContent.getBytes())).when(smbFile).getInputStream();

        // When: doFile is called
        assertDoesNotThrow(() -> networkExplorer.doFile(request, response, smbFile));

        // Then: Verify headers and output stream writes
        verify(response).setContentType(anyString());
        verify(response).setHeader("Content-Length", String.valueOf(fileLength));
        verify(response.getOutputStream(), atLeastOnce()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test the doDirectory method directly.
     */
    @Test
    void testDoDirectory() throws IOException {
        // Given: A mock SmbFile representing a directory with some entries
        SmbFile[] files = {mock(SmbFile.class), mock(SmbFile.class)};
        when(files[0].getName()).thenReturn("file1.txt");
        when(files[1].getName()).thenReturn("dir1/");
        when(files[1].isDirectory()).thenReturn(true);
        when(smbFile.listFiles()).thenReturn(files);
        when(request.getParameter("fmt")).thenReturn("detail");

        // When: doDirectory is called
        assertDoesNotThrow(() -> networkExplorer.doDirectory(request, response, smbFile));

        // Then: Verify the output contains the names of the directory entries
        String output = stringWriter.toString();
        assert (output.contains("file1.txt"));
        assert (output.contains("dir1/"));
    }

    /**
     * Test for the openFile method - using reflection since it's private.
     */
    @Test
    void testOpenFile() throws Exception {
        // Given: A pathInfo and server name
        String pathInfo = "/server/share/file.txt";
        String server = "server";

        // Use reflection to access the private openFile method
        java.lang.reflect.Method openFileMethod = NetworkExplorer.class.getDeclaredMethod("openFile", String.class, String.class);
        openFileMethod.setAccessible(true);

        // When: openFile is called via reflection
        SmbFile resultFile = (SmbFile) openFileMethod.invoke(networkExplorer, pathInfo, server);

        // Then: Assert that the returned SmbFile is not null
        assertNotNull(resultFile);
    }

    /**
     * Test for the openFile method when server is null - using reflection since it's private.
     */
    @Test
    void testOpenFile_NullServer() throws Exception {
        // Given: A pathInfo and a null server name
        String pathInfo = "/";

        // Use reflection to access the private openFile method
        java.lang.reflect.Method openFileMethod = NetworkExplorer.class.getDeclaredMethod("openFile", String.class, String.class);
        openFileMethod.setAccessible(true);

        // When: openFile is called via reflection
        SmbFile resultFile = (SmbFile) openFileMethod.invoke(networkExplorer, pathInfo, null);

        // Then: Assert that the returned SmbFile is not null
        assertNotNull(resultFile);
    }
}
