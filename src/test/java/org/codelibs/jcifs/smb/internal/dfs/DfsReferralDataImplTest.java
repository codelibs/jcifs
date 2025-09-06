package org.codelibs.jcifs.smb.internal.dfs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.codelibs.jcifs.smb.DfsReferralData;
import org.codelibs.jcifs.smb.internal.smb1.trans2.Trans2GetDfsReferralResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Test class for DfsReferralDataImpl
 */
@DisplayName("DfsReferralDataImpl Tests")
class DfsReferralDataImplTest {

    private DfsReferralDataImpl referralData;

    @Mock
    private Referral mockReferral;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        referralData = new DfsReferralDataImpl();
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should initialize with self-referencing next")
        void testConstructorInitialization() {
            DfsReferralDataImpl data = new DfsReferralDataImpl();
            assertNotNull(data.next());
            assertSame(data, data.next());
        }
    }

    @Nested
    @DisplayName("Unwrap Tests")
    class UnwrapTests {

        @Test
        @DisplayName("Should unwrap to DfsReferralData interface")
        void testUnwrapToDfsReferralData() {
            DfsReferralData unwrapped = referralData.unwrap(DfsReferralData.class);
            assertSame(referralData, unwrapped);
        }

        @Test
        @DisplayName("Should unwrap to DfsReferralDataInternal interface")
        void testUnwrapToDfsReferralDataInternal() {
            DfsReferralDataInternal unwrapped = referralData.unwrap(DfsReferralDataInternal.class);
            assertSame(referralData, unwrapped);
        }

        @Test
        @DisplayName("Should unwrap to DfsReferralDataImpl class")
        void testUnwrapToDfsReferralDataImpl() {
            DfsReferralDataImpl unwrapped = referralData.unwrap(DfsReferralDataImpl.class);
            assertSame(referralData, unwrapped);
        }

        @Test
        @DisplayName("Should throw ClassCastException for incompatible type")
        void testUnwrapToIncompatibleType() {
            // Create a mock class that extends DfsReferralData but is not compatible
            class IncompatibleReferralData implements DfsReferralData {
                @Override
                public <T extends DfsReferralData> T unwrap(Class<T> type) {
                    return null;
                }

                @Override
                public long getExpiration() {
                    return 0;
                }

                @Override
                public int getPathConsumed() {
                    return 0;
                }

                @Override
                public String getDomain() {
                    return null;
                }

                @Override
                public String getLink() {
                    return null;
                }

                @Override
                public String getServer() {
                    return null;
                }

                @Override
                public String getShare() {
                    return null;
                }

                @Override
                public String getPath() {
                    return null;
                }

                @Override
                public DfsReferralData next() {
                    return null;
                }
            }

            assertThrows(ClassCastException.class, () -> {
                referralData.unwrap(IncompatibleReferralData.class);
            });
        }
    }

    @Nested
    @DisplayName("Property Getter and Setter Tests")
    class PropertyTests {

        @Test
        @DisplayName("Should get and set domain")
        void testDomain() {
            assertNull(referralData.getDomain());
            referralData.setDomain("EXAMPLE.COM");
            assertEquals("EXAMPLE.COM", referralData.getDomain());
        }

        @Test
        @DisplayName("Should get and set link")
        void testLink() {
            assertNull(referralData.getLink());
            referralData.setLink("\\\\server\\share\\link");
            assertEquals("\\\\server\\share\\link", referralData.getLink());
        }

        @Test
        @DisplayName("Should get and set key")
        void testKey() {
            assertNull(referralData.getKey());
            referralData.setKey("cache-key-123");
            assertEquals("cache-key-123", referralData.getKey());
        }

        @Test
        @DisplayName("Should get server")
        void testGetServer() {
            assertNull(referralData.getServer());
        }

        @Test
        @DisplayName("Should get share")
        void testGetShare() {
            assertNull(referralData.getShare());
        }

        @Test
        @DisplayName("Should get path")
        void testGetPath() {
            assertNull(referralData.getPath());
        }

        @Test
        @DisplayName("Should get expiration")
        void testGetExpiration() {
            assertEquals(0, referralData.getExpiration());
        }

        @Test
        @DisplayName("Should get path consumed")
        void testGetPathConsumed() {
            assertEquals(0, referralData.getPathConsumed());
        }

        @Test
        @DisplayName("Should get flags")
        void testGetFlags() {
            assertEquals(0, referralData.getFlags());
        }

        @Test
        @DisplayName("Should get TTL")
        void testGetTtl() {
            assertEquals(0, referralData.getTtl());
        }

        @Test
        @DisplayName("Should get resolveHashes")
        void testIsResolveHashes() {
            assertFalse(referralData.isResolveHashes());
        }

        @Test
        @DisplayName("Should get and set intermediate flag")
        void testIntermediate() {
            assertFalse(referralData.isIntermediate());
            referralData.intermediate();
            assertTrue(referralData.isIntermediate());
        }
    }

    @Nested
    @DisplayName("Cache Management Tests")
    class CacheManagementTests {

        private Map<String, DfsReferralDataInternal> cacheMap;

        @BeforeEach
        void setUpCache() {
            cacheMap = new HashMap<>();
        }

        @Test
        @DisplayName("Should set cache map")
        void testSetCacheMap() {
            referralData.setCacheMap(cacheMap);
            // Verify by checking replaceCache doesn't throw
            referralData.setKey("test-key");
            referralData.replaceCache();
            assertEquals(referralData, cacheMap.get("test-key"));
        }

        @Test
        @DisplayName("Should replace cache entry with key")
        void testReplaceCache() {
            String key = "cache-key";
            referralData.setKey(key);
            referralData.setCacheMap(cacheMap);

            referralData.replaceCache();

            assertEquals(referralData, cacheMap.get(key));
        }

        @Test
        @DisplayName("Should not replace cache when map is null")
        void testReplaceCacheWithNullMap() {
            referralData.setKey("key");
            // Should not throw exception
            referralData.replaceCache();
        }

        @Test
        @DisplayName("Should not replace cache when key is null")
        void testReplaceCacheWithNullKey() {
            referralData.setCacheMap(cacheMap);
            // Should not throw exception
            referralData.replaceCache();
            assertTrue(cacheMap.isEmpty());
        }
    }

    @Nested
    @DisplayName("Linked List Operations Tests")
    class LinkedListTests {

        @Test
        @DisplayName("Should append referral data")
        void testAppend() {
            DfsReferralDataImpl second = new DfsReferralDataImpl();
            DfsReferralDataImpl third = new DfsReferralDataImpl();

            referralData.append(second);
            assertEquals(second, referralData.next());
            assertEquals(referralData, second.next());

            referralData.append(third);
            assertEquals(third, referralData.next());
            assertEquals(second, third.next());
            assertEquals(referralData, second.next());
        }

        @Test
        @DisplayName("Should handle next() correctly")
        void testNext() {
            DfsReferralDataImpl second = new DfsReferralDataImpl();
            referralData.append(second);

            DfsReferralDataImpl next = referralData.next();
            assertSame(second, next);
        }
    }

    @Nested
    @DisplayName("Path Consumed Tests")
    class PathConsumedTests {

        @Test
        @DisplayName("Should strip path consumed correctly")
        void testStripPathConsumed() {
            // Set initial pathConsumed using fromReferral
            setupReferralDataWithPathConsumed(10);

            referralData.stripPathConsumed(5);
            assertEquals(5, referralData.getPathConsumed());
        }

        @Test
        @DisplayName("Should strip exact path consumed")
        void testStripExactPathConsumed() {
            setupReferralDataWithPathConsumed(10);

            referralData.stripPathConsumed(10);
            assertEquals(0, referralData.getPathConsumed());
        }

        @Test
        @DisplayName("Should throw exception when stripping more than consumed")
        void testStripMoreThanConsumed() {
            setupReferralDataWithPathConsumed(5);

            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> referralData.stripPathConsumed(10));
            assertEquals("Stripping more than consumed", exception.getMessage());
        }

        private void setupReferralDataWithPathConsumed(int consumed) {
            when(mockReferral.getTtl()).thenReturn(300);
            when(mockReferral.getRFlags()).thenReturn(0);
            when(mockReferral.getNode()).thenReturn("\\server\\share\\path");

            String reqPath = "\\\\server\\share\\path\\file";
            // Ensure consumed is within bounds to avoid StringIndexOutOfBoundsException
            consumed = Math.min(consumed, reqPath.length());

            referralData = DfsReferralDataImpl.fromReferral(mockReferral, reqPath, System.currentTimeMillis() + 10000, consumed);
        }
    }

    @Nested
    @DisplayName("Domain and Host Fixup Tests")
    class FixupTests {

        @Test
        @DisplayName("Should fixup domain for uppercase NetBIOS name")
        void testFixupDomainWithNetBIOSName() {
            // Setup with uppercase server name
            setupReferralWithServer("SERVER");

            referralData.fixupDomain("example.com");

            assertEquals("SERVER.example.com", referralData.getServer());
        }

        @Test
        @DisplayName("Should not fixup domain for qualified name")
        void testFixupDomainWithQualifiedName() {
            setupReferralWithServer("server.example.com");

            referralData.fixupDomain("otherdomain.com");

            assertEquals("server.example.com", referralData.getServer());
        }

        @Test
        @DisplayName("Should not fixup domain for mixed case name")
        void testFixupDomainWithMixedCase() {
            setupReferralWithServer("Server");

            referralData.fixupDomain("example.com");

            assertEquals("Server", referralData.getServer());
        }

        @Test
        @DisplayName("Should fixup host for matching FQDN")
        void testFixupHostWithMatchingFQDN() {
            setupReferralWithServer("SERVER");

            referralData.fixupHost("server.example.com");

            assertEquals("server.example.com", referralData.getServer());
        }

        @Test
        @DisplayName("Should not fixup host for non-matching FQDN")
        void testFixupHostWithNonMatchingFQDN() {
            setupReferralWithServer("SERVER");

            referralData.fixupHost("other.example.com");

            assertEquals("SERVER", referralData.getServer());
        }

        @Test
        @DisplayName("Should not fixup host for qualified server name")
        void testFixupHostWithQualifiedServer() {
            setupReferralWithServer("server.domain.com");

            referralData.fixupHost("server.example.com");

            assertEquals("server.domain.com", referralData.getServer());
        }

        private void setupReferralWithServer(String server) {
            when(mockReferral.getTtl()).thenReturn(300);
            when(mockReferral.getRFlags()).thenReturn(0);
            when(mockReferral.getNode()).thenReturn("\\" + server + "\\share\\path");

            referralData =
                    DfsReferralDataImpl.fromReferral(mockReferral, "\\\\server\\share\\path", System.currentTimeMillis() + 10000, 10);
        }
    }

    @Nested
    @DisplayName("FromReferral Factory Method Tests")
    class FromReferralTests {

        @Test
        @DisplayName("Should create from referral with regular flags")
        void testFromReferralRegular() {
            when(mockReferral.getTtl()).thenReturn(600);
            when(mockReferral.getRFlags()).thenReturn(0);
            when(mockReferral.getNode()).thenReturn("\\server.example.com\\share\\folder");

            String reqPath = "\\\\server\\share\\folder\\file.txt";
            long expire = System.currentTimeMillis() + 60000;
            int consumed = 20;

            DfsReferralDataImpl result = DfsReferralDataImpl.fromReferral(mockReferral, reqPath, expire, consumed);

            assertNotNull(result);
            assertEquals(600, result.getTtl());
            assertEquals(0, result.getFlags());
            assertEquals(expire, result.getExpiration());
            assertEquals("server.example.com", result.getServer());
            assertEquals("share", result.getShare());
            assertEquals("folder", result.getPath());
            assertEquals(consumed, result.getPathConsumed());
        }

        @Test
        @DisplayName("Should create from referral with name list flag")
        void testFromReferralWithNameListFlag() {
            when(mockReferral.getTtl()).thenReturn(300);
            when(mockReferral.getRFlags()).thenReturn(Trans2GetDfsReferralResponse.FLAGS_NAME_LIST_REFERRAL);
            when(mockReferral.getExpandedNames()).thenReturn(new String[] { "\\SERVER1", "\\SERVER2" });

            String reqPath = "\\\\domain\\root\\path";
            long expire = System.currentTimeMillis() + 30000;
            int consumed = 15;

            DfsReferralDataImpl result = DfsReferralDataImpl.fromReferral(mockReferral, reqPath, expire, consumed);

            assertNotNull(result);
            assertEquals("server1", result.getServer());
            assertNull(result.getShare());
            assertNull(result.getPath());
            assertEquals(consumed, result.getPathConsumed());
        }

        @Test
        @DisplayName("Should use special name when no expanded names")
        void testFromReferralWithSpecialName() {
            when(mockReferral.getTtl()).thenReturn(300);
            when(mockReferral.getRFlags()).thenReturn(Trans2GetDfsReferralResponse.FLAGS_NAME_LIST_REFERRAL);
            when(mockReferral.getExpandedNames()).thenReturn(new String[0]);
            when(mockReferral.getSpecialName()).thenReturn("\\SPECIAL");

            String reqPath = "\\\\domain\\root";
            long expire = System.currentTimeMillis() + 30000;
            int consumed = 10;

            DfsReferralDataImpl result = DfsReferralDataImpl.fromReferral(mockReferral, reqPath, expire, consumed);

            assertEquals("special", result.getServer());
        }

        @Test
        @DisplayName("Should adjust path consumed for trailing slash")
        void testFromReferralWithTrailingSlash() {
            when(mockReferral.getTtl()).thenReturn(300);
            when(mockReferral.getRFlags()).thenReturn(0);
            when(mockReferral.getNode()).thenReturn("\\server\\share");

            String reqPath = "\\\\server\\share\\";
            long expire = System.currentTimeMillis() + 30000;
            int consumed = 15; // reqPath.length() = 15

            DfsReferralDataImpl result = DfsReferralDataImpl.fromReferral(mockReferral, reqPath, expire, consumed);

            // Should have adjusted pathConsumed to exclude trailing slash
            assertEquals(14, result.getPathConsumed());
        }

        @ParameterizedTest
        @ValueSource(strings = { "\\server", "\\server\\share", "\\server\\share\\path", "\\server\\share\\path\\subpath\\file.txt" })
        @DisplayName("Should parse various node formats")
        void testFromReferralWithVariousNodeFormats(String node) {
            when(mockReferral.getTtl()).thenReturn(300);
            when(mockReferral.getRFlags()).thenReturn(0);
            when(mockReferral.getNode()).thenReturn(node);

            DfsReferralDataImpl result =
                    DfsReferralDataImpl.fromReferral(mockReferral, "\\\\server\\share\\path", System.currentTimeMillis() + 30000, 10);

            assertNotNull(result);
            assertNotNull(result.getServer());
        }
    }

    @Nested
    @DisplayName("Combine Tests")
    class CombineTests {

        @Test
        @DisplayName("Should combine two referral data objects")
        void testCombine() {
            // Setup first referral
            DfsReferralDataImpl first = new DfsReferralDataImpl();
            when(mockReferral.getTtl()).thenReturn(300);
            when(mockReferral.getRFlags()).thenReturn(0);
            when(mockReferral.getNode()).thenReturn("\\server1\\share1\\path1");
            first = DfsReferralDataImpl.fromReferral(mockReferral, "\\\\server1\\share1\\path1", System.currentTimeMillis() + 10000, 20);

            // Setup second referral
            DfsReferralDataImpl second = new DfsReferralDataImpl();
            when(mockReferral.getNode()).thenReturn("\\server2\\share2\\path2");
            second = DfsReferralDataImpl.fromReferral(mockReferral, "\\\\server2\\share2\\path2", System.currentTimeMillis() + 20000, 15);
            second.setDomain("DOMAIN");

            // Combine
            DfsReferralDataInternal combined = first.combine(second);

            assertNotNull(combined);
            assertEquals("server2", combined.getServer());
            assertEquals("share2", combined.getShare());
            assertEquals("path2", combined.getPath());
            assertEquals("DOMAIN", combined.getDomain());
            assertEquals(second.getExpiration(), combined.getExpiration());

            // Path consumed should be combined
            int expectedPathConsumed = 20 + 15;
            if (first.getPath() != null) {
                expectedPathConsumed -= (first.getPath().length() + 1);
            }
            assertEquals(expectedPathConsumed, combined.getPathConsumed());
        }

        @Test
        @DisplayName("Should combine when first has null path")
        void testCombineWithNullPath() {
            // Create first with null path
            DfsReferralDataImpl first = new DfsReferralDataImpl();
            when(mockReferral.getTtl()).thenReturn(300);
            when(mockReferral.getRFlags()).thenReturn(Trans2GetDfsReferralResponse.FLAGS_NAME_LIST_REFERRAL);
            when(mockReferral.getExpandedNames()).thenReturn(new String[] { "\\SERVER1" });
            first = DfsReferralDataImpl.fromReferral(mockReferral, "\\\\domain\\root", System.currentTimeMillis() + 10000, 10);

            // Create second
            DfsReferralDataImpl second = new DfsReferralDataImpl();
            when(mockReferral.getRFlags()).thenReturn(0);
            when(mockReferral.getNode()).thenReturn("\\server2\\share2");
            second = DfsReferralDataImpl.fromReferral(mockReferral, "\\\\server2\\share2", System.currentTimeMillis() + 20000, 15);

            DfsReferralDataInternal combined = first.combine(second);

            assertNotNull(combined);
            assertEquals(10 + 15, combined.getPathConsumed());
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should generate correct string representation")
        void testToString() {
            when(mockReferral.getTtl()).thenReturn(600);
            when(mockReferral.getRFlags()).thenReturn(4);
            when(mockReferral.getNode()).thenReturn("\\server.example.com\\share\\folder");

            long expiration = System.currentTimeMillis() + 60000;
            referralData = DfsReferralDataImpl.fromReferral(mockReferral, "\\\\server\\share\\folder", expiration, 20);
            referralData.setLink("\\\\link\\target");

            String result = referralData.toString();

            assertTrue(result.contains("DfsReferralData["));
            assertTrue(result.contains("pathConsumed=20"));
            assertTrue(result.contains("server=server.example.com"));
            assertTrue(result.contains("share=share"));
            assertTrue(result.contains("link=\\\\link\\target"));
            assertTrue(result.contains("path=folder"));
            assertTrue(result.contains("ttl=600"));
            assertTrue(result.contains("expiration=" + expiration));
            assertTrue(result.contains("remain="));
            assertTrue(result.endsWith("]"));
        }

        @Test
        @DisplayName("Should handle null values in toString")
        void testToStringWithNulls() {
            String result = referralData.toString();

            assertTrue(result.contains("server=null"));
            assertTrue(result.contains("share=null"));
            assertTrue(result.contains("link=null"));
            assertTrue(result.contains("path=null"));
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsHashCodeTests {

        private DfsReferralDataImpl data1;
        private DfsReferralDataImpl data2;

        @BeforeEach
        void setupData() {
            when(mockReferral.getTtl()).thenReturn(300);
            when(mockReferral.getRFlags()).thenReturn(0);
            when(mockReferral.getNode()).thenReturn("\\server\\share\\path");

            String reqPath = "\\\\server\\share\\path";
            // Use valid consumed value within string bounds (reqPath.length() = 19)
            int consumed = Math.min(19, reqPath.length());

            data1 = DfsReferralDataImpl.fromReferral(mockReferral, reqPath, System.currentTimeMillis() + 10000, consumed);

            data2 = DfsReferralDataImpl.fromReferral(mockReferral, reqPath, System.currentTimeMillis() + 10000, consumed);
        }

        @Test
        @DisplayName("Should be equal for same values")
        void testEquals() {
            assertEquals(data1, data2);
            assertEquals(data2, data1);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void testEqualsSelf() {
            assertEquals(data1, data1);
        }

        @Test
        @DisplayName("Should have same hashCode for equal objects")
        void testHashCodeConsistency() {
            assertEquals(data1.hashCode(), data2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal to null")
        void testNotEqualToNull() {
            assertNotEquals(data1, null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void testNotEqualToDifferentType() {
            assertNotEquals(data1, "string");
        }

        @Test
        @DisplayName("Should not be equal with different server")
        void testNotEqualDifferentServer() {
            when(mockReferral.getNode()).thenReturn("\\otherserver\\share\\path");
            DfsReferralDataImpl other =
                    DfsReferralDataImpl.fromReferral(mockReferral, "\\\\otherserver\\share\\path", System.currentTimeMillis() + 10000, 20);

            assertNotEquals(data1, other);
        }

        @Test
        @DisplayName("Should not be equal with different share")
        void testNotEqualDifferentShare() {
            when(mockReferral.getNode()).thenReturn("\\server\\othershare\\path");
            DfsReferralDataImpl other =
                    DfsReferralDataImpl.fromReferral(mockReferral, "\\\\server\\othershare\\path", System.currentTimeMillis() + 10000, 20);

            assertNotEquals(data1, other);
        }

        @Test
        @DisplayName("Should not be equal with different path")
        void testNotEqualDifferentPath() {
            when(mockReferral.getNode()).thenReturn("\\server\\share\\otherpath");
            DfsReferralDataImpl other =
                    DfsReferralDataImpl.fromReferral(mockReferral, "\\\\server\\share\\otherpath", System.currentTimeMillis() + 10000, 20);

            assertNotEquals(data1, other);
        }

        @Test
        @DisplayName("Should not be equal with different pathConsumed")
        void testNotEqualDifferentPathConsumed() {
            String reqPath = "\\\\server\\share\\path\\longer\\path";
            when(mockReferral.getNode()).thenReturn("\\server\\share\\path");
            DfsReferralDataImpl other = DfsReferralDataImpl.fromReferral(mockReferral, reqPath, System.currentTimeMillis() + 10000,
                    Math.min(30, reqPath.length()));

            assertNotEquals(data1, other);
        }
    }

    @Nested
    @DisplayName("DfsPathSplit Tests")
    class DfsPathSplitTests {

        @ParameterizedTest
        @CsvSource({ "'\\server', 'server', '', ''", "'\\server\\share', 'server', 'share', ''",
                "'\\server\\share\\path', 'server', 'share', 'path'",
                "'\\server\\share\\path\\file.txt', 'server', 'share', 'path\\file.txt'",
                "'\\server.domain.com\\share\\deep\\path\\structure', 'server.domain.com', 'share', 'deep\\path\\structure'" })
        @DisplayName("Should split DFS paths correctly")
        void testDfsPathSplit(String node, String expectedServer, String expectedShare, String expectedPath) {
            when(mockReferral.getTtl()).thenReturn(300);
            when(mockReferral.getRFlags()).thenReturn(0);
            when(mockReferral.getNode()).thenReturn(node);

            DfsReferralDataImpl result =
                    DfsReferralDataImpl.fromReferral(mockReferral, "\\\\test\\path", System.currentTimeMillis() + 10000, 10);

            assertEquals(expectedServer, result.getServer());
            // The implementation returns empty strings as empty strings, not null
            assertEquals(expectedShare.isEmpty() ? "" : expectedShare, result.getShare());
            assertEquals(expectedPath.isEmpty() ? "" : expectedPath, result.getPath());
        }

        @Test
        @DisplayName("Should handle path with multiple backslashes")
        void testPathWithMultipleBackslashes() {
            when(mockReferral.getTtl()).thenReturn(300);
            when(mockReferral.getRFlags()).thenReturn(0);
            when(mockReferral.getNode()).thenReturn("\\server\\\\share\\\\path");

            DfsReferralDataImpl result =
                    DfsReferralDataImpl.fromReferral(mockReferral, "\\\\test\\path", System.currentTimeMillis() + 10000, 10);

            assertNotNull(result.getServer());
            // Empty components between double backslashes are handled
        }
    }

    @Nested
    @DisplayName("Edge Cases and Boundary Tests")
    class EdgeCasesTests {

        @ParameterizedTest
        @NullAndEmptySource
        @DisplayName("Should handle null and empty domains")
        void testNullAndEmptyDomains(String domain) {
            referralData.setDomain(domain);
            assertEquals(domain, referralData.getDomain());
        }

        @ParameterizedTest
        @NullAndEmptySource
        @DisplayName("Should handle null and empty links")
        void testNullAndEmptyLinks(String link) {
            referralData.setLink(link);
            assertEquals(link, referralData.getLink());
        }

        @ParameterizedTest
        @NullAndEmptySource
        @DisplayName("Should handle null and empty keys")
        void testNullAndEmptyKeys(String key) {
            referralData.setKey(key);
            assertEquals(key, referralData.getKey());
        }

        @Test
        @DisplayName("Should handle very long paths")
        void testVeryLongPaths() {
            StringBuilder longPath = new StringBuilder("\\server\\share");
            for (int i = 0; i < 100; i++) {
                longPath.append("\\subfolder").append(i);
            }

            when(mockReferral.getTtl()).thenReturn(300);
            when(mockReferral.getRFlags()).thenReturn(0);
            when(mockReferral.getNode()).thenReturn(longPath.toString());

            DfsReferralDataImpl result =
                    DfsReferralDataImpl.fromReferral(mockReferral, longPath.toString(), System.currentTimeMillis() + 10000, 50);

            assertNotNull(result);
            assertEquals("server", result.getServer());
            assertEquals("share", result.getShare());
            assertTrue(result.getPath().length() > 0);
        }

        @Test
        @DisplayName("Should handle special characters in server names")
        void testSpecialCharactersInServerName() {
            when(mockReferral.getTtl()).thenReturn(300);
            when(mockReferral.getRFlags()).thenReturn(0);
            when(mockReferral.getNode()).thenReturn("\\server-01.example_domain.com\\share$\\path");

            DfsReferralDataImpl result =
                    DfsReferralDataImpl.fromReferral(mockReferral, "\\\\test\\path", System.currentTimeMillis() + 10000, 10);

            assertEquals("server-01.example_domain.com", result.getServer());
            assertEquals("share$", result.getShare());
            assertEquals("path", result.getPath());
        }

        @Test
        @DisplayName("Should handle negative expiration times")
        void testNegativeExpiration() {
            when(mockReferral.getTtl()).thenReturn(300);
            when(mockReferral.getRFlags()).thenReturn(0);
            when(mockReferral.getNode()).thenReturn("\\server\\share");

            long pastExpiration = System.currentTimeMillis() - 10000;
            DfsReferralDataImpl result = DfsReferralDataImpl.fromReferral(mockReferral, "\\\\server\\share", pastExpiration, 10);

            assertEquals(pastExpiration, result.getExpiration());
            // toString should show negative remain time
            String str = result.toString();
            assertTrue(str.contains("remain="));
        }
    }
}
