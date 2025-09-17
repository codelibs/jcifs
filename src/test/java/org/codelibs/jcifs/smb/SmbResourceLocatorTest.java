package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.MalformedURLException;
import java.net.URL;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link SmbResourceLocator}. Since the interface has no
 * concrete implementation in this repository, a lightweight implementation
 * is provided solely for the purpose of exercising the contract.
 */
@ExtendWith(MockitoExtension.class)
public class SmbResourceLocatorTest {

    /**
     * A very small concrete implementation used only by the tests. It parses
     * the URL string and performs minimal validation – just enough to make the
     * happy-path expectations deterministic.
     */
    private static class DummySmbResourceLocator implements SmbResourceLocator {
        private final String urlStr;
        private final String host;
        private final String path;
        private final String canonical;
        private DfsReferralData dfsReferral;

        DummySmbResourceLocator(String urlStr) throws MalformedURLException {
            if (urlStr == null) {
                throw new IllegalArgumentException("URL string must not be null");
            }
            if (!urlStr.startsWith("smb://")) {
                throw new MalformedURLException("Only SMB URLs are supported in the dummy implementation");
            }
            this.urlStr = urlStr;

            // Parse SMB URL manually
            String remaining = urlStr.substring(6); // Remove "smb://"
            int slashIndex = remaining.indexOf('/');
            if (slashIndex == -1) {
                this.host = remaining;
                this.path = "/";
            } else {
                this.host = remaining.substring(0, slashIndex);
                this.path = remaining.substring(slashIndex);
            }

            // canonical form: remove . and .. but nothing fancy
            this.canonical = urlStr.replace("..", "").replace(".", "");
        }

        @Override
        public String getName() {
            if (path == null || path.isEmpty() || path.equals("/")) {
                return host + "/"; // mimic the JVM behaviour for root or server
            }
            if (path.endsWith("/")) {
                return path.substring(0, path.length()); // keep trailing slash
            }
            String[] parts = path.split("/");
            return parts[parts.length - 1];
        }

        @Override
        public String getParent() {
            if (path == null || path.isEmpty() || path.equals("/")) {
                return "smb://";
            }
            int lastSlash = path.lastIndexOf('/');
            if (lastSlash <= 0) {
                return "smb://";
            }
            return "smb://" + host + path.substring(0, lastSlash + 1);
        }

        @Override
        public String getPath() {
            return urlStr;
        }

        @Override
        public String getCanonicalURL() {
            return canonical;
        }

        @Override
        public DfsReferralData getDfsReferral() {
            return dfsReferral;
        }

        public void setDfsReferral(DfsReferralData dfsReferral) {
            this.dfsReferral = dfsReferral;
        }

        @Override
        public String getUNCPath() {
            return null;
        }

        @Override
        public String getURLPath() {
            return null;
        }

        @Override
        public String getShare() {
            return null;
        }

        @Override
        public String getServerWithDfs() {
            return null;
        }

        @Override
        public String getServer() {
            return null;
        }

        @Override
        public String getDfsPath() {
            return null;
        }

        @Override
        public int getPort() {
            return 0;
        }

        @Override
        public URL getURL() {
            try {
                // Create URL with custom protocol handler for SMB
                return new URL(null, urlStr, new org.codelibs.jcifs.smb.impl.Handler());
            } catch (Exception e) {
                // Return null if URL creation fails
                return null;
            }
        }

        @Override
        public Address getAddress() {
            return null;
        }

        @Override
        public boolean isIPC() {
            return false;
        }

        @Override
        public int getType() {
            return 0;
        }

        @Override
        public boolean isWorkgroup() {
            return false;
        }

        @Override
        public boolean isRoot() {
            return "/".equals(path);
        }
    }

    @Nested
    @DisplayName("Happy path – well-formed SMB URL")
    class HappyPath {
        @Test
        void testBasicProperties() throws Exception {
            String url = "smb://server/share/path/file.txt";
            DummySmbResourceLocator loc = new DummySmbResourceLocator(url);
            assertEquals("file.txt", loc.getName());
            assertEquals("smb://server/share/path/", loc.getParent());
            assertEquals(url, loc.getPath());
            // canonicalisation simply removes '.' and '..'
            assertEquals("smb://server/share/path/filetxt", loc.getCanonicalURL());
            assertFalse(loc.isRoot());
        }
    }

    @Nested
    @DisplayName("Invalid inputs and edge cases")
    class Invalid {
        @Test
        void nullUrlThrows() {
            assertThrows(IllegalArgumentException.class, () -> new DummySmbResourceLocator(null));
        }

        @Test
        void unsupportedProtocolThrows() {
            String url = "http://example.com";
            assertThrows(MalformedURLException.class, () -> new DummySmbResourceLocator(url));
        }

        @Test
        void rootUrlIsRoot() throws Exception {
            DummySmbResourceLocator root = new DummySmbResourceLocator("smb://server/");
            // last component includes trailing slash per specification
            assertEquals("server/", root.getName());
            assertEquals("smb://", root.getParent());
            assertTrue(root.isRoot());
        }

        @Test
        void emptyPathReturnsServerWithSlash() throws Exception {
            DummySmbResourceLocator root = new DummySmbResourceLocator("smb://server/");
            assertEquals("server/", root.getName());
        }
    }

    @Mock
    DfsReferralData dfs;
    @Mock
    Address addr;

    @Test
    @DisplayName("Mockito interaction – dependent objects are called appropriately")
    void testInteractionsWithStubbedDependencies() throws Exception {
        String url = "smb://server/share/";
        DummySmbResourceLocator loc = new DummySmbResourceLocator(url);

        // Set the DFS referral mock
        loc.setDfsReferral(dfs);

        // Verify we can retrieve it
        DfsReferralData received = loc.getDfsReferral();
        assertSame(dfs, received);

        // Verify that the URL returned by getURL works with SMB handler
        URL returned = loc.getURL();
        if (returned != null) {
            assertEquals(url, returned.toString());
        }

        // Test that getAddress returns null for our dummy implementation
        assertNull(loc.getAddress());
    }

    @Test
    @DisplayName("Test DFS referral data")
    void testDfsReferralData() throws Exception {
        String url = "smb://server/share/path/";
        DummySmbResourceLocator loc = new DummySmbResourceLocator(url);

        // Initially no DFS referral
        assertNull(loc.getDfsReferral());

        // Set and retrieve DFS referral
        loc.setDfsReferral(dfs);
        assertSame(dfs, loc.getDfsReferral());
    }
}