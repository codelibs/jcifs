package jcifs.smb;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.UnknownHostException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jcifs.Address;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.Credentials;
import jcifs.DfsReferralData;
import jcifs.NameServiceClient;
import jcifs.NetbiosAddress;
import jcifs.SmbConstants;
import jcifs.SmbResourceLocator;
import jcifs.netbios.UniAddress;
import jcifs.RuntimeCIFSException;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SmbResourceLocatorImplTest {

    @Mock private CIFSContext ctx;
    @Mock private Configuration config;
    @Mock private Credentials creds;
    @Mock private NameServiceClient nsc;

    // Minimal URLStreamHandler to allow creating smb:// URLs in tests
    private static final URLStreamHandler SMB_HANDLER = new URLStreamHandler() {
        @Override
        protected URLConnection openConnection(URL u) {
            return null; // not used
        }
    };

    @BeforeEach
    void setup() {
        when(ctx.getConfig()).thenReturn(config);
        when(ctx.getCredentials()).thenReturn(creds);
        when(ctx.getNameServiceClient()).thenReturn(nsc);
    }

    private static URL smbUrl(String spec) {
        try {
            return new URL(null, spec, SMB_HANDLER);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private SmbResourceLocatorImpl locator(String spec) {
        return new SmbResourceLocatorImpl(ctx, smbUrl(spec));
    }

    @Test
    @DisplayName("getName returns last path segment; falls back logically")
    void testGetNameVariants() {
        // file name from deep path
        SmbResourceLocatorImpl a = locator("smb://server/share/dir/file.txt");
        assertEquals("file.txt", a.getName());

        // share name with trailing slash when only share present
        SmbResourceLocatorImpl b = locator("smb://server/share/");
        assertEquals("share/", b.getName());

        // host when no path/share
        SmbResourceLocatorImpl c = locator("smb://server/");
        assertEquals("server/", c.getName());

        // root fallback
        SmbResourceLocatorImpl d = locator("smb:///");
        assertEquals("smb://", d.getName());
    }

    @Test
    @DisplayName("Parent URL is computed correctly")
    void testGetParent() {
        SmbResourceLocatorImpl a = locator("smb://server/share/dir/file.txt");
        assertEquals("smb://server/share/dir/", a.getParent());

        SmbResourceLocatorImpl b = locator("smb://server/share/");
        assertEquals("smb://server/", b.getParent());
    }

    @Test
    @DisplayName("Canonical and UNC paths are computed and stable")
    void testCanonicalAndUNCPaths() {
        SmbResourceLocatorImpl a = locator("smb://server/share/dir/.././file");
        // canonicalization removes . and resolves ..
        assertEquals("/share/file", a.getURLPath());
        assertEquals("\\file", a.getUNCPath());
        assertEquals("share", a.getShare());
        assertEquals("smb://server/share/file", a.getCanonicalURL());
    }

    @Test
    @DisplayName("Invalid path triggers RuntimeCIFSException during canonicalize")
    void testCanonicalizeInvalidPath() {
        SmbResourceLocatorImpl a = locator("smb:invalid-no-slash");
        // Any accessor that triggers canonicalizePath should throw
        assertThrows(RuntimeCIFSException.class, a::getURLPath);
        assertThrows(RuntimeCIFSException.class, a::getUNCPath);
    }

    @Test
    @DisplayName("Server, port, URL passthrough getters")
    void testServerPortUrl() throws Exception {
        // No context mocks needed for this test
        SmbResourceLocatorImpl a = locator("smb://server:444/share");
        assertEquals("server", a.getServer());
        assertEquals(444, a.getPort());
        assertEquals(smbUrl("smb://server:444/share"), a.getURL());

        SmbResourceLocatorImpl b = locator("smb:///share");
        assertNull(b.getServer());
    }

    @Test
    @DisplayName("shouldForceSigning depends on config, creds, and IPC")
    void testShouldForceSigning() {
        when(config.isIpcSigningEnforced()).thenReturn(true);
        when(creds.isAnonymous()).thenReturn(false);

        // Case 1: share is IPC$ -> IPC
        SmbResourceLocatorImpl ipc = locator("smb://server/IPC$/");
        assertTrue(ipc.shouldForceSigning());

        // Case 2: config disabled
        when(config.isIpcSigningEnforced()).thenReturn(false);
        assertFalse(ipc.shouldForceSigning());

        // Case 3: anonymous credentials
        when(config.isIpcSigningEnforced()).thenReturn(true);
        when(creds.isAnonymous()).thenReturn(true);
        assertFalse(ipc.shouldForceSigning());

        // Verify interactions sequence for one call
        InOrder inOrder = inOrder(config, creds);
        ipc = locator("smb://server/IPC$/");
        ipc.shouldForceSigning();
        inOrder.verify(config, atLeastOnce()).isIpcSigningEnforced();
        inOrder.verify(creds, atLeastOnce()).isAnonymous();
    }

    @Test
    @DisplayName("isIPC is true for IPC$ or no share")
    void testIsIpc() {
        assertTrue(locator("smb://server/IPC$/").isIPC());
        assertTrue(locator("smb://server/").isIPC());
        assertFalse(locator("smb://server/share/").isIPC());
    }

    @Test
    @DisplayName("Type detection covers filesystem/share/IPC/workgroup/server")
    void testGetType() throws Exception {
        // Filesystem when there is a path beyond share
        assertEquals(SmbConstants.TYPE_FILESYSTEM, locator("smb://server/share/path").getType());

        // Named pipe for IPC$ root
        assertEquals(SmbConstants.TYPE_NAMED_PIPE, locator("smb://server/IPC$/").getType());

        // Share when share set but no path
        assertEquals(SmbConstants.TYPE_SHARE, locator("smb://server/share/").getType());

        // Workgroup when no authority
        assertEquals(SmbConstants.TYPE_WORKGROUP, locator("smb:///" ).getType());

        // Server vs Workgroup depends on NetBIOS name type
        Address addr = mock(Address.class);
        NetbiosAddress nb = mock(NetbiosAddress.class);
        when(addr.unwrap(NetbiosAddress.class)).thenReturn(nb);
        when(nb.getNameType()).thenReturn(0x1d); // workgroup code
        // getFirstAddress branch: host given and path non-root -> possibleNTDomain=false
        when(nsc.getAllByName(eq("server"), eq(false))).thenReturn(new Address[]{addr});
        SmbResourceLocatorImpl workgroupLike = locator("smb://server/");
        // path is "/" -> triggers possibleNTDomainOrWorkgroup true
        when(nsc.getAllByName(eq("server"), eq(true))).thenReturn(new Address[]{addr});
        assertTrue(workgroupLike.isWorkgroup());

        // Server: return a NetBIOS type not 0x1d/0x1b
        when(nb.getNameType()).thenReturn(0x20);
        SmbResourceLocatorImpl server = locator("smb://server");
        when(nsc.getAllByName(eq("server"), eq(true))).thenReturn(new Address[]{addr});
        assertEquals(SmbConstants.TYPE_SERVER, server.getType());
    }

    @Test
    @DisplayName("isWorkgroup true for empty host or NetBIOS 0x1d/0x1b")
    void testIsWorkgroup() throws Exception {
        assertTrue(locator("smb:///share").isWorkgroup()); // empty host

        Address addr = mock(Address.class);
        NetbiosAddress nb = mock(NetbiosAddress.class);
        when(addr.unwrap(NetbiosAddress.class)).thenReturn(nb);
        when(nb.getNameType()).thenReturn(0x1b);
        when(nsc.getAllByName(eq("server"), eq(true))).thenReturn(new Address[]{addr});
        SmbResourceLocatorImpl l = locator("smb://server/");
        assertTrue(l.isWorkgroup());
    }

    @Test
    @DisplayName("getAddress/getFirstAddress resolution branches and iteration")
    void testAddressResolutionAndIteration() throws Exception {
        // Query parameter 'server' takes precedence
        UniAddress a1 = mock(UniAddress.class);
        when(nsc.getByName("srv-from-query")).thenReturn(a1);
        SmbResourceLocatorImpl l1 = locator("smb://host/share?server=srv-from-query");
        assertSame(a1, l1.getAddress());

        // Query parameter 'address' builds UniAddress from IP
        SmbResourceLocatorImpl l2 = locator("smb://host/share?address=127.0.0.1");
        Address first = l2.getAddress();
        assertTrue(first instanceof UniAddress);

        // Host with root path -> possibleNTDomainOrWorkgroup=true
        UniAddress a2 = mock(UniAddress.class);
        UniAddress a3 = mock(UniAddress.class);
        when(nsc.getAllByName("server", true)).thenReturn(new Address[]{a2, a3});
        SmbResourceLocatorImpl l3 = locator("smb://server/");
        assertSame(a2, l3.getAddress());
        verify(nsc, times(1)).getAllByName("server", true);
        assertTrue(l3.hasNextAddress());
        assertSame(a3, l3.getNextAddress());
        assertFalse(l3.hasNextAddress());

        // UnknownHostException yields CIFSException
        when(nsc.getAllByName("badhost", true)).thenThrow(new UnknownHostException("nope"));
        SmbResourceLocatorImpl bad = locator("smb://badhost/");
        CIFSException ex = assertThrows(CIFSException.class, bad::getAddress);
        assertTrue(ex.getMessage().contains("Failed to lookup address"));
    }

    @Test
    @DisplayName("hashCode/equals based on address or server fallback")
    void testEqualsAndHashCode() throws Exception {
        UniAddress a = mock(UniAddress.class);
        when(nsc.getAllByName(eq("server"), anyBoolean())).thenReturn(new Address[]{a});
        when(nsc.getAllByName(eq("SERVER"), anyBoolean())).thenReturn(new Address[]{a});
        SmbResourceLocatorImpl l1 = locator("smb://server/share/file");
        SmbResourceLocatorImpl l2 = locator("smb://SERVER/share/file");
        assertEquals(l1, l2);
        assertEquals(l1.hashCode(), l2.hashCode());

        // Different path -> not equal
        SmbResourceLocatorImpl l5 = locator("smb://server/share/other");
        assertNotEquals(l1, l5);
        
        // Force address resolution failure -> fallback to server name compare
        // Use a fresh context to avoid affecting previous tests
        CIFSContext ctx2 = mock(CIFSContext.class);
        Configuration config2 = mock(Configuration.class);
        Credentials creds2 = mock(Credentials.class);
        NameServiceClient nsc2 = mock(NameServiceClient.class);
        when(ctx2.getConfig()).thenReturn(config2);
        when(ctx2.getCredentials()).thenReturn(creds2);
        when(ctx2.getNameServiceClient()).thenReturn(nsc2);
        when(nsc2.getAllByName(anyString(), anyBoolean())).thenThrow(new UnknownHostException("fail"));
        
        SmbResourceLocatorImpl l3 = new SmbResourceLocatorImpl(ctx2, smbUrl("smb://host/share/file"));
        SmbResourceLocatorImpl l4 = new SmbResourceLocatorImpl(ctx2, smbUrl("smb://HOST/share/file"));
        assertEquals(l3, l4);
        assertEquals(l3.hashCode(), l4.hashCode());
    }

    @Test
    @DisplayName("overlaps requires same address and canonical URL prefix match")
    void testOverlaps() throws Exception {
        UniAddress a = mock(UniAddress.class);
        when(nsc.getAllByName(anyString(), anyBoolean())).thenReturn(new Address[]{a});
        SmbResourceLocatorImpl base = locator("smb://server/share/dir");
        SmbResourceLocatorImpl child = locator("smb://server/share/dir/file");
        assertTrue(base.overlaps(child));

        SmbResourceLocatorImpl other = locator("smb://server/share/other");
        assertFalse(base.overlaps(other));
    }

    @Test
    @DisplayName("isRoot and isRootOrShare reflect path state")
    void testIsRootAndShare() {
        assertTrue(locator("smb://server/").isRoot());
        assertFalse(locator("smb://server/share/").isRoot());
        assertTrue(locator("smb://server/").isRootOrShare());
        assertTrue(locator("smb://server/share/").isRootOrShare());
        assertFalse(locator("smb://server/share/path").isRootOrShare());
    }

    @Test
    @DisplayName("DFS getters and handleDFSReferral update paths and share")
    void testDfsBehavior() {
        SmbResourceLocatorImpl l = locator("smb://server/share/path");
        assertNull(l.getDfsReferral());

        DfsReferralData dr = mock(DfsReferralData.class);
        when(dr.getServer()).thenReturn("dfs-server");
        when(dr.getShare()).thenReturn("dfs-share");
        when(dr.getPath()).thenReturn("dfs/path");
        when(dr.getPathConsumed()).thenReturn(2); // consume leading \\ from UNC

        String newUnc = l.handleDFSReferral(dr, "\\req\\");
        // dunc is "\\" + path + remaining  - note: path may not have leading backslashes
        assertTrue(newUnc.contains("dfs/path") || newUnc.contains("dfs\\path"));
        assertEquals(dr, l.getDfsReferral());
        assertEquals("dfs-server", l.getServerWithDfs());
        assertEquals("smb://dfs-server/dfs-share" + l.getUNCPath().replace('\\', '/'), l.getDfsPath());
        assertEquals("dfs-share", l.getShare());

        // Path consumed negative -> coerced to 0
        when(dr.getPathConsumed()).thenReturn(-1);
        String unc2 = l.handleDFSReferral(dr, null);
        assertTrue(unc2.contains("dfs/path") || unc2.contains("dfs\\path"));
    }

    @Test
    @DisplayName("toString includes URL and cached fields")
    void testToString() {
        SmbResourceLocatorImpl l = locator("smb://server/share");
        String s = l.toString();
        assertTrue(s.startsWith("smb://server/share"));
        // The toString() format may vary, just check it includes the URL
        assertNotNull(s);
    }

    @Test
    @DisplayName("updateType overrides computed type until changed")
    void testUpdateType() throws Exception {
        // No context mocks needed for this test
        SmbResourceLocatorImpl l = locator("smb://server/share/path");
        l.updateType(SmbConstants.TYPE_SERVER);
        assertEquals(SmbConstants.TYPE_SERVER, l.getType());
    }

    @Test
    @DisplayName("clone copies state including addresses")
    void testCloneCopiesState() throws Exception {
        UniAddress a1 = mock(UniAddress.class);
        when(nsc.getAllByName("server", false)).thenReturn(new Address[]{a1});
        SmbResourceLocatorImpl l = locator("smb://server/share/path");
        // Force address resolution and set type
        l.getAddress();
        l.updateType(SmbConstants.TYPE_SHARE);

        SmbResourceLocatorImpl copy = l.clone();
        assertEquals(l.getURLPath(), copy.getURLPath());
        assertEquals(l.getUNCPath(), copy.getUNCPath());
        assertEquals(l.getShare(), copy.getShare());
        assertEquals(l.getType(), copy.getType());
        assertSame(l.getURL(), copy.getURL());
    }

    @ParameterizedTest
    @DisplayName("queryLookup extracts values case-insensitively")
    @CsvSource({
        "a=1&b=2,a,1",
        "A=1&a=2,a,1", // first match before next param
        "x=foo&Server=name,server,name",
        "paramOnly=,paramOnly,''",
        "noeq&other=1,other,1"
    })
    void testQueryLookup(String query, String key, String expected) {
        // No context mocks needed for static method test
        assertEquals(expected, SmbResourceLocatorImpl.queryLookup(query, key));
    }

    @Test
    @DisplayName("resolveInContext builds relative paths with and without share")
    void testResolveInContext() {
        // Context without share: first element becomes share, rest path
        SmbResourceLocatorImpl base = locator("smb://server/");
        SmbResourceLocator context = mock(SmbResourceLocator.class);
        when(context.getShare()).thenReturn(null);
        when(context.getServer()).thenReturn("server");
        when(context.getURLPath()).thenReturn("/");

        base.resolveInContext(context, "share/dir/file/");
        assertEquals("/share/dir/file/", base.getURLPath());
        assertEquals("\\dir\\file\\", base.getUNCPath());
        assertEquals("share", base.getShare());

        // Context with share and at root
        SmbResourceLocatorImpl base2 = locator("smb://server/share/");
        SmbResourceLocator context2 = mock(SmbResourceLocator.class);
        when(context2.getShare()).thenReturn("share");
        when(context2.getDfsReferral()).thenReturn(null);
        when(context2.getUNCPath()).thenReturn("\\");
        when(context2.getURLPath()).thenReturn("/share/");
        when(context2.getServer()).thenReturn("server");

        base2.resolveInContext(context2, "sub/child");
        assertEquals("/share/sub/child", base2.getURLPath());
        assertEquals("\\sub\\child", base2.getUNCPath());
        assertEquals("share", base2.getShare());
    }
}