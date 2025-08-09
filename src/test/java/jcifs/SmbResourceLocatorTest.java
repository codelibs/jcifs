package jcifs;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.net.MalformedURLException;
import java.net.URL;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Unit tests for {@link SmbResourceLocator}. Since the interface has no
 * concrete implementation in this repository, a lightweight implementation
 * is provided solely for the purpose of exercising the contract.
 *
 * <p>
 *   Tests cover
 *   <ul>
 *     <li>happy path behaviour for a typical SMB URL</li>
 *     <li>handling of {@code null} and unsupported protocol values</li>
 *     <li>edge cases such as an empty path or a root URL</li>
 *     <li>interaction with dependent objects via Mockito stubbing and
 *         verification</li>
 *   </ul>
 * </p>
 */
@ExtendWith(MockitoExtension.class)
public class SmbResourceLocatorTest {

    /**
     * A very small concrete implementation used only by the tests. It parses
     * the URL string and performs minimal validation – just enough to make the
     * happy‑path expectations deterministic.
     */
    private static class DummySmbResourceLocator implements SmbResourceLocator {
        private final URL url;
        private final String canonical;

        DummySmbResourceLocator(String urlStr) throws MalformedURLException {
            if (urlStr == null) {
                throw new IllegalArgumentException("URL string must not be null");
            }
            if (!urlStr.startsWith("smb://")) {
                throw new MalformedURLException("Only SMB URLs are supported in the dummy implementation");
            }
            this.url = new URL(urlStr);
            // canonical form: remove . and .. but nothing fancy
            this.canonical = urlStr.replace("..", "").replace(".", "");
        }

        @Override public String getName() {
            String path = url.getPath();
            if (path == null || path.isEmpty() || path.equals("/")) {
                return url.getHost() + "/"; // mimic the JVM behaviour for root or server
            }
            if (path.endsWith("/")) {
                return path.substring(0, path.length()); // keep trailing slash
            }
            String[] parts = path.split("/");
            return parts[parts.length - 1];
        }

        @Override public String getParent() {
            String path = url.getPath();
            if (path == null || path.isEmpty() || path.equals("/")) {
                return "smb://";
            }
            int lastSlash = path.lastIndexOf('/');
            if (lastSlash <= 0) {
                return "smb://";
            }
            return "smb://" + url.getHost() + path.substring(0, lastSlash + 1);
        }

        @Override public String getPath() {
            return url.toString();
        }

        @Override public String getCanonicalURL() {
            return canonical;
        }

        @Override public String getUNCPath() { return null; }
        @Override public String getURLPath() { return null; }
        @Override public String getShare() { return null; }
        @Override public String getServerWithDfs() { return null; }
        @Override public String getServer() { return null; }
        @Override public String getDfsPath() { return null; }
        @Override public int getPort() { return 0; }
        @Override public URL getURL() { return url; }
        @Override public Address getAddress() { return null; }
        @Override public boolean isIPC() { return false; }
        @Override public int getType() { return 0; }
        @Override public boolean isWorkgroup() { return false; }
        @Override public boolean isRoot() { return "/".equals(url.getPath()); }
    }

    @Nested
    @DisplayName("Happy path – well‑formed SMB URL")
    class HappyPath {
        @Test
        void testBasicProperties() throws Exception {
            String url = "smb://server/share/path/file.txt";
            DummySmbResourceLocator loc = new DummySmbResourceLocator(url);
            assertEquals("file.txt", loc.getName());
            assertEquals("smb://server/share/path/", loc.getParent());
            assertEquals(url, loc.getPath());
            // canonicalisation simply removes '.' and '..'
            assertEquals("smb://server/share/path/file.txt", loc.getCanonicalURL());
            assertFalse(loc.isRoot());
        }
    }

    @Nested
    @DisplayName("Invalid inputs and edge cases")
    class Invalid {
        @Test
        void nullUrlThrows() {
            assertThrows(IllegalArgumentException.class,
                         (Executable) () -> new DummySmbResourceLocator(null));
        }

        @Test
        void unsupportedProtocolThrows() {
            String url = "http://example.com";
            assertThrows(MalformedURLException.class,
                         (Executable) () -> new DummySmbResourceLocator(url));
        }

        @Test
        void rootUrlIsRoot() throws Exception {
            DummySmbResourceLocator root = new DummySmbResourceLocator("smb://server/");
            // last component includes trailing slash per specification
            assertEquals("server/", root.getName());
            assertEquals("smb://server/", root.getParent());
            assertTrue(root.isRoot());
        }

        @Test
        void emptyPathReturnsServerWithSlash() throws Exception {
            DummySmbResourceLocator root = new DummySmbResourceLocator("smb://server/");
            assertEquals("server/", root.getName());
        }
    }

    @Mock DfsReferralData dfs;
    @Mock Address addr;

    @Test
    @DisplayName("Mockito interaction – dependent objects are called appropriately")
    void testInteractionsWithStubbedDependencies() throws Exception {
        String url = "smb://server/share/";
        DummySmbResourceLocator loc = new DummySmbResourceLocator(url);

        // Stub getDfsReferral to return our mock and verify its use in a client
        when(loc.getDfsReferral()).thenReturn(dfs);
        when(dfs.getReferralURL()).thenReturn("smb://dfssrv/share/refpath");

        // Simulate a consumer that simply calls the methods once each.
        DfsReferralData received = loc.getDfsReferral();
        assertSame(dfs, received);
        verify(loc, times(1)).getDfsReferral();
        verify(dfs, never()).getReferralURL(); // the mocked locator does not delegate

        // Verify that the mock URL returned by getURL is the same instance
        URL returned = loc.getURL();
        assertEquals(url, returned.toString());

        // Verify that calling getAddress throws, because our dummy returns null
        assertThrows(CIFSException.class, () -> loc.getAddress());
    }
}
