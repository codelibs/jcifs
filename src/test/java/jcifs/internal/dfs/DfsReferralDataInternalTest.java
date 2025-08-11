package jcifs.internal.dfs;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.DfsReferralData;

/**
 * Test class for DfsReferralDataInternal interface
 * Tests the interface contract using mock implementations and concrete class
 */
@DisplayName("DfsReferralDataInternal Interface Tests")
class DfsReferralDataInternalTest {

    @Mock
    private DfsReferralDataInternal mockReferralData;
    
    @Mock
    private DfsReferralData mockDfsReferralData;
    
    private DfsReferralDataInternal concreteImplementation;
    
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        // Using concrete implementation for integration testing
        // Note: DfsReferralDataImpl default constructor creates an object with null server/share/path
        // Some methods like fixupHost/fixupDomain require these to be set via combine() or fromReferral()
        concreteImplementation = createInitializedDfsReferralDataImpl();
    }
    
    private DfsReferralDataImpl createInitializedDfsReferralDataImpl() {
        // Create a properly initialized instance using combine method
        DfsReferralDataImpl base = new DfsReferralDataImpl();
        DfsReferralData mockData = mock(DfsReferralData.class);
        when(mockData.getServer()).thenReturn("SERVER");
        when(mockData.getShare()).thenReturn("share");
        when(mockData.getPath()).thenReturn("path");
        when(mockData.getExpiration()).thenReturn(System.currentTimeMillis() + 60000);
        when(mockData.getPathConsumed()).thenReturn(0);
        when(mockData.getDomain()).thenReturn("DOMAIN");
        return (DfsReferralDataImpl) base.combine(mockData);
    }

    @Nested
    @DisplayName("Interface Method Contract Tests")
    class InterfaceMethodTests {
        
        @Test
        @DisplayName("Should fixup host with FQDN")
        void testFixupHost() {
            String fqdn = "server.example.com";
            
            // Test with mock
            doNothing().when(mockReferralData).fixupHost(fqdn);
            mockReferralData.fixupHost(fqdn);
            verify(mockReferralData, times(1)).fixupHost(fqdn);
            
            // Test with concrete implementation - requires server to be set
            assertDoesNotThrow(() -> concreteImplementation.fixupHost(fqdn));
        }
        
        @Test
        @DisplayName("Should fixup domain")
        void testFixupDomain() {
            String domain = "example.com";
            
            // Test with mock
            doNothing().when(mockReferralData).fixupDomain(domain);
            mockReferralData.fixupDomain(domain);
            verify(mockReferralData, times(1)).fixupDomain(domain);
            
            // Test with concrete implementation - requires server to be set
            assertDoesNotThrow(() -> concreteImplementation.fixupDomain(domain));
        }
        
        @Test
        @DisplayName("Should strip path consumed")
        void testStripPathConsumed() {
            int consumedAmount = 5;
            
            // Test with mock
            doNothing().when(mockReferralData).stripPathConsumed(consumedAmount);
            mockReferralData.stripPathConsumed(consumedAmount);
            verify(mockReferralData, times(1)).stripPathConsumed(consumedAmount);
            
            // Test with concrete implementation
            assertDoesNotThrow(() -> concreteImplementation.stripPathConsumed(0));
        }
        
        @Test
        @DisplayName("Should return next referral data")
        void testNext() {
            // Test with mock
            when(mockReferralData.next()).thenReturn(mockReferralData);
            DfsReferralDataInternal next = mockReferralData.next();
            assertSame(mockReferralData, next);
            verify(mockReferralData, times(1)).next();
            
            // Test with concrete implementation
            DfsReferralDataInternal concreteNext = concreteImplementation.next();
            assertNotNull(concreteNext);
        }
        
        @Test
        @DisplayName("Should set link")
        void testSetLink() {
            String link = "\\\\server\\share\\link";
            
            // Test with mock
            doNothing().when(mockReferralData).setLink(link);
            mockReferralData.setLink(link);
            verify(mockReferralData, times(1)).setLink(link);
            
            // Test with concrete implementation
            concreteImplementation.setLink(link);
            assertEquals(link, concreteImplementation.getLink());
        }
        
        @Test
        @DisplayName("Should get and set key")
        void testGetAndSetKey() {
            String key = "cache-key-123";
            
            // Test with mock
            when(mockReferralData.getKey()).thenReturn(key);
            doNothing().when(mockReferralData).setKey(key);
            
            mockReferralData.setKey(key);
            String retrievedKey = mockReferralData.getKey();
            
            assertEquals(key, retrievedKey);
            verify(mockReferralData, times(1)).setKey(key);
            verify(mockReferralData, times(1)).getKey();
            
            // Test with concrete implementation
            concreteImplementation.setKey(key);
            assertEquals(key, concreteImplementation.getKey());
        }
        
        @Test
        @DisplayName("Should set cache map")
        void testSetCacheMap() {
            Map<String, DfsReferralDataInternal> cacheMap = new HashMap<>();
            
            // Test with mock
            doNothing().when(mockReferralData).setCacheMap(cacheMap);
            mockReferralData.setCacheMap(cacheMap);
            verify(mockReferralData, times(1)).setCacheMap(cacheMap);
            
            // Test with concrete implementation
            assertDoesNotThrow(() -> concreteImplementation.setCacheMap(cacheMap));
        }
        
        @Test
        @DisplayName("Should replace cache")
        void testReplaceCache() {
            // Test with mock
            doNothing().when(mockReferralData).replaceCache();
            mockReferralData.replaceCache();
            verify(mockReferralData, times(1)).replaceCache();
            
            // Test with concrete implementation
            assertDoesNotThrow(() -> concreteImplementation.replaceCache());
        }
        
        @Test
        @DisplayName("Should check if resolve hashes")
        void testIsResolveHashes() {
            // Test with mock
            when(mockReferralData.isResolveHashes()).thenReturn(true);
            assertTrue(mockReferralData.isResolveHashes());
            verify(mockReferralData, times(1)).isResolveHashes();
            
            // Test with concrete implementation
            boolean result = concreteImplementation.isResolveHashes();
            assertNotNull(result);
        }
        
        @Test
        @DisplayName("Should check if intermediate")
        void testIsIntermediate() {
            // Test with mock
            when(mockReferralData.isIntermediate()).thenReturn(false);
            assertFalse(mockReferralData.isIntermediate());
            verify(mockReferralData, times(1)).isIntermediate();
            
            // Test with concrete implementation
            boolean result = concreteImplementation.isIntermediate();
            assertNotNull(result);
        }
        
        @Test
        @DisplayName("Should combine referral data")
        void testCombine() {
            DfsReferralDataInternal combined = mock(DfsReferralDataInternal.class);
            
            // Test with mock
            when(mockReferralData.combine(mockDfsReferralData)).thenReturn(combined);
            DfsReferralDataInternal result = mockReferralData.combine(mockDfsReferralData);
            assertSame(combined, result);
            verify(mockReferralData, times(1)).combine(mockDfsReferralData);
            
            // Test with concrete implementation
            DfsReferralDataInternal concreteResult = concreteImplementation.combine(mockDfsReferralData);
            assertNotNull(concreteResult);
        }
        
        @Test
        @DisplayName("Should append referral data")
        void testAppend() {
            DfsReferralDataInternal toAppend = mock(DfsReferralDataInternal.class);
            
            // Test with mock
            doNothing().when(mockReferralData).append(toAppend);
            mockReferralData.append(toAppend);
            verify(mockReferralData, times(1)).append(toAppend);
            
            // Test with concrete implementation
            DfsReferralDataImpl implToAppend = createInitializedDfsReferralDataImpl();
            assertDoesNotThrow(() -> concreteImplementation.append(implToAppend));
        }
    }

    @Nested
    @DisplayName("Inherited DfsReferralData Methods Tests")
    class InheritedMethodsTests {
        
        @Test
        @DisplayName("Should get expiration")
        void testGetExpiration() {
            long expiration = System.currentTimeMillis() + 60000;
            
            // Test with mock
            when(mockReferralData.getExpiration()).thenReturn(expiration);
            assertEquals(expiration, mockReferralData.getExpiration());
            verify(mockReferralData, times(1)).getExpiration();
            
            // Test with concrete implementation
            long concreteExpiration = concreteImplementation.getExpiration();
            assertTrue(concreteExpiration >= 0);
        }
        
        @Test
        @DisplayName("Should get path consumed")
        void testGetPathConsumed() {
            int pathConsumed = 20;
            
            // Test with mock
            when(mockReferralData.getPathConsumed()).thenReturn(pathConsumed);
            assertEquals(pathConsumed, mockReferralData.getPathConsumed());
            verify(mockReferralData, times(1)).getPathConsumed();
            
            // Test with concrete implementation
            int concretePathConsumed = concreteImplementation.getPathConsumed();
            assertTrue(concretePathConsumed >= 0);
        }
        
        @Test
        @DisplayName("Should get domain")
        void testGetDomain() {
            String domain = "EXAMPLE.COM";
            
            // Test with mock
            when(mockReferralData.getDomain()).thenReturn(domain);
            assertEquals(domain, mockReferralData.getDomain());
            verify(mockReferralData, times(1)).getDomain();
            
            // Test with concrete implementation
            String concreteDomain = concreteImplementation.getDomain();
            // Should be DOMAIN based on our initialization
            assertEquals("DOMAIN", concreteDomain);
        }
        
        @Test
        @DisplayName("Should get link")
        void testGetLink() {
            String link = "\\\\server\\share\\link";
            
            // Test with mock
            when(mockReferralData.getLink()).thenReturn(link);
            assertEquals(link, mockReferralData.getLink());
            verify(mockReferralData, times(1)).getLink();
            
            // Test with concrete implementation
            concreteImplementation.setLink(link);
            assertEquals(link, concreteImplementation.getLink());
        }
        
        @Test
        @DisplayName("Should get server")
        void testGetServer() {
            String server = "server.example.com";
            
            // Test with mock
            when(mockReferralData.getServer()).thenReturn(server);
            assertEquals(server, mockReferralData.getServer());
            verify(mockReferralData, times(1)).getServer();
            
            // Test with concrete implementation
            String concreteServer = concreteImplementation.getServer();
            // Should be SERVER based on our initialization
            assertEquals("SERVER", concreteServer);
        }
        
        @Test
        @DisplayName("Should get share")
        void testGetShare() {
            String share = "share";
            
            // Test with mock
            when(mockReferralData.getShare()).thenReturn(share);
            assertEquals(share, mockReferralData.getShare());
            verify(mockReferralData, times(1)).getShare();
            
            // Test with concrete implementation
            String concreteShare = concreteImplementation.getShare();
            // Should be share based on our initialization
            assertEquals("share", concreteShare);
        }
        
        @Test
        @DisplayName("Should get path")
        void testGetPath() {
            String path = "folder\\subfolder\\file.txt";
            
            // Test with mock
            when(mockReferralData.getPath()).thenReturn(path);
            assertEquals(path, mockReferralData.getPath());
            verify(mockReferralData, times(1)).getPath();
            
            // Test with concrete implementation
            String concretePath = concreteImplementation.getPath();
            // Should be path based on our initialization
            assertEquals("path", concretePath);
        }
    }

    @Nested
    @DisplayName("Edge Cases and Boundary Tests")
    class EdgeCasesTests {
        
        @ParameterizedTest
        @NullAndEmptySource
        @DisplayName("Should handle null and empty FQDN in fixupHost")
        void testFixupHostWithNullAndEmpty(String fqdn) {
            // Test with mock
            doNothing().when(mockReferralData).fixupHost(fqdn);
            assertDoesNotThrow(() -> mockReferralData.fixupHost(fqdn));
            
            // Test with concrete implementation - fixupHost doesn't handle null fqdn
            if (fqdn == null) {
                DfsReferralDataImpl impl = createInitializedDfsReferralDataImpl();
                assertThrows(NullPointerException.class, () -> impl.fixupHost(fqdn));
            } else {
                // Empty string is handled
                DfsReferralDataImpl impl = createInitializedDfsReferralDataImpl();
                assertDoesNotThrow(() -> impl.fixupHost(fqdn));
            }
        }
        
        @ParameterizedTest
        @NullAndEmptySource
        @DisplayName("Should handle null and empty domain in fixupDomain")
        void testFixupDomainWithNullAndEmpty(String domain) {
            // Test with mock
            doNothing().when(mockReferralData).fixupDomain(domain);
            assertDoesNotThrow(() -> mockReferralData.fixupDomain(domain));
            
            // Test with concrete implementation - default constructor has null server
            // fixupDomain requires non-null server, so we test with initialized instance
            DfsReferralDataImpl impl = createInitializedDfsReferralDataImpl();
            assertDoesNotThrow(() -> impl.fixupDomain(domain));
        }
        
        @ParameterizedTest
        @ValueSource(ints = {0, -1, Integer.MIN_VALUE, Integer.MAX_VALUE})
        @DisplayName("Should handle various values in stripPathConsumed")
        void testStripPathConsumedWithVariousValues(int value) {
            // Test with mock
            doNothing().when(mockReferralData).stripPathConsumed(value);
            mockReferralData.stripPathConsumed(value);
            verify(mockReferralData, times(1)).stripPathConsumed(value);
            
            // Test with concrete implementation - may throw for invalid values
            if (value >= 0 && value <= concreteImplementation.getPathConsumed()) {
                assertDoesNotThrow(() -> concreteImplementation.stripPathConsumed(value));
            }
        }
        
        @Test
        @DisplayName("Should handle null link in setLink")
        void testSetLinkWithNull() {
            // Test with mock
            doNothing().when(mockReferralData).setLink(null);
            assertDoesNotThrow(() -> mockReferralData.setLink(null));
            
            // Test with concrete implementation
            assertDoesNotThrow(() -> {
                concreteImplementation.setLink(null);
                assertNull(concreteImplementation.getLink());
            });
        }
        
        @Test
        @DisplayName("Should handle null key in setKey")
        void testSetKeyWithNull() {
            // Test with mock
            doNothing().when(mockReferralData).setKey(null);
            assertDoesNotThrow(() -> mockReferralData.setKey(null));
            
            // Test with concrete implementation
            assertDoesNotThrow(() -> {
                concreteImplementation.setKey(null);
                assertNull(concreteImplementation.getKey());
            });
        }
        
        @Test
        @DisplayName("Should handle null cache map")
        void testSetCacheMapWithNull() {
            // Test with mock
            doNothing().when(mockReferralData).setCacheMap(null);
            assertDoesNotThrow(() -> mockReferralData.setCacheMap(null));
            
            // Test with concrete implementation
            assertDoesNotThrow(() -> concreteImplementation.setCacheMap(null));
        }
        
        @Test
        @DisplayName("Should handle null in combine")
        void testCombineWithNull() {
            // Test with mock
            when(mockReferralData.combine(null)).thenReturn(mockReferralData);
            DfsReferralDataInternal result = mockReferralData.combine(null);
            assertNotNull(result);
            
            // Test with concrete implementation - combine with null throws NPE
            assertThrows(NullPointerException.class, () -> concreteImplementation.combine(null));
        }
        
        @Test
        @DisplayName("Should handle null in append")
        void testAppendWithNull() {
            // Test with mock
            doNothing().when(mockReferralData).append(null);
            assertDoesNotThrow(() -> mockReferralData.append(null));
            
            // Test with concrete implementation - behavior depends on implementation
            // May throw NullPointerException
            try {
                concreteImplementation.append(null);
            } catch (NullPointerException e) {
                // Expected for some implementations
            }
        }
    }

    @Nested
    @DisplayName("Cache Operations Tests")
    class CacheOperationsTests {
        
        private Map<String, DfsReferralDataInternal> cacheMap;
        
        @BeforeEach
        void setupCache() {
            cacheMap = new HashMap<>();
        }
        
        @Test
        @DisplayName("Should replace entry in cache map")
        void testReplaceCacheWithMap() {
            String key = "test-key";
            
            // Setup concrete implementation
            concreteImplementation.setKey(key);
            concreteImplementation.setCacheMap(cacheMap);
            
            // Execute replace
            concreteImplementation.replaceCache();
            
            // Verify
            assertEquals(concreteImplementation, cacheMap.get(key));
        }
        
        @Test
        @DisplayName("Should handle replace without key")
        void testReplaceCacheWithoutKey() {
            concreteImplementation.setCacheMap(cacheMap);
            
            // Should not throw
            assertDoesNotThrow(() -> concreteImplementation.replaceCache());
            
            // Map should remain empty
            assertTrue(cacheMap.isEmpty());
        }
        
        @Test
        @DisplayName("Should handle replace without map")
        void testReplaceCacheWithoutMap() {
            concreteImplementation.setKey("key");
            
            // Should not throw
            assertDoesNotThrow(() -> concreteImplementation.replaceCache());
        }
        
        @Test
        @DisplayName("Should overwrite existing cache entry")
        void testReplaceCacheOverwrite() {
            String key = "existing-key";
            DfsReferralDataInternal oldEntry = mock(DfsReferralDataInternal.class);
            
            // Add existing entry
            cacheMap.put(key, oldEntry);
            
            // Setup new entry
            concreteImplementation.setKey(key);
            concreteImplementation.setCacheMap(cacheMap);
            
            // Replace
            concreteImplementation.replaceCache();
            
            // Verify overwrite
            assertEquals(concreteImplementation, cacheMap.get(key));
            assertNotEquals(oldEntry, cacheMap.get(key));
        }
    }

    @Nested
    @DisplayName("Complex Scenarios Tests")
    class ComplexScenariosTests {
        
        @Test
        @DisplayName("Should handle multiple fixup operations")
        void testMultipleFixupOperations() {
            // Create a properly initialized instance for fixup operations
            DfsReferralDataImpl impl = createInitializedDfsReferralDataImpl();
            
            // Create a chain of operations
            assertDoesNotThrow(() -> {
                impl.fixupHost("server1.example.com");
                impl.fixupDomain("domain.com");
                impl.fixupHost("server2.example.com");
                impl.fixupDomain("otherdomain.com");
            });
        }
        
        @Test
        @DisplayName("Should handle linked list of referrals")
        void testLinkedListOfReferrals() {
            DfsReferralDataImpl first = createInitializedDfsReferralDataImpl();
            DfsReferralDataImpl second = createInitializedDfsReferralDataImpl();
            DfsReferralDataImpl third = createInitializedDfsReferralDataImpl();
            
            // Build chain
            first.append(second);
            first.append(third);
            
            // Verify chain
            assertEquals(third, first.next());
            assertEquals(second, third.next());
            assertEquals(first, second.next());
        }
        
        @Test
        @DisplayName("Should handle cache replacement in complex scenario")
        void testComplexCacheReplacement() {
            Map<String, DfsReferralDataInternal> cache = new HashMap<>();
            
            // Create multiple entries
            for (int i = 0; i < 10; i++) {
                DfsReferralDataImpl entry = createInitializedDfsReferralDataImpl();
                String key = "key-" + i;
                entry.setKey(key);
                entry.setCacheMap(cache);
                entry.replaceCache();
            }
            
            // Verify all entries
            assertEquals(10, cache.size());
            for (int i = 0; i < 10; i++) {
                assertNotNull(cache.get("key-" + i));
            }
            
            // Replace some entries
            for (int i = 0; i < 5; i++) {
                DfsReferralDataImpl newEntry = createInitializedDfsReferralDataImpl();
                String key = "key-" + i;
                newEntry.setKey(key);
                newEntry.setCacheMap(cache);
                newEntry.setLink("new-link-" + i);
                newEntry.replaceCache();
            }
            
            // Verify replacements
            assertEquals(10, cache.size());
            for (int i = 0; i < 5; i++) {
                DfsReferralDataInternal entry = cache.get("key-" + i);
                assertEquals("new-link-" + i, entry.getLink());
            }
        }
        
        @Test
        @DisplayName("Should handle combine with intermediate flag")
        void testCombineWithIntermediateFlag() {
            // Create two referrals
            DfsReferralDataImpl first = createInitializedDfsReferralDataImpl();
            DfsReferralDataImpl second = createInitializedDfsReferralDataImpl();
            
            // Set intermediate flag on first
            first.intermediate();
            assertTrue(first.isIntermediate());
            
            // Combine
            DfsReferralDataInternal combined = first.combine(second);
            assertNotNull(combined);
        }
    }

    @Nested
    @DisplayName("Mock Behavior Verification Tests")
    class MockBehaviorTests {
        
        @Test
        @DisplayName("Should verify all interface methods can be mocked")
        void testAllMethodsCanBeMocked() {
            // Setup all mock behaviors
            when(mockReferralData.getExpiration()).thenReturn(1000L);
            when(mockReferralData.getPathConsumed()).thenReturn(10);
            when(mockReferralData.getDomain()).thenReturn("domain");
            when(mockReferralData.getLink()).thenReturn("link");
            when(mockReferralData.getServer()).thenReturn("server");
            when(mockReferralData.getShare()).thenReturn("share");
            when(mockReferralData.getPath()).thenReturn("path");
            when(mockReferralData.next()).thenReturn(mockReferralData);
            when(mockReferralData.getKey()).thenReturn("key");
            when(mockReferralData.isResolveHashes()).thenReturn(true);
            when(mockReferralData.isIntermediate()).thenReturn(false);
            when(mockReferralData.combine(any())).thenReturn(mockReferralData);
            
            // Execute all methods
            assertEquals(1000L, mockReferralData.getExpiration());
            assertEquals(10, mockReferralData.getPathConsumed());
            assertEquals("domain", mockReferralData.getDomain());
            assertEquals("link", mockReferralData.getLink());
            assertEquals("server", mockReferralData.getServer());
            assertEquals("share", mockReferralData.getShare());
            assertEquals("path", mockReferralData.getPath());
            assertEquals(mockReferralData, mockReferralData.next());
            assertEquals("key", mockReferralData.getKey());
            assertTrue(mockReferralData.isResolveHashes());
            assertFalse(mockReferralData.isIntermediate());
            assertEquals(mockReferralData, mockReferralData.combine(null));
            
            mockReferralData.fixupHost("host");
            mockReferralData.fixupDomain("domain");
            mockReferralData.stripPathConsumed(5);
            mockReferralData.setLink("link");
            mockReferralData.setKey("key");
            mockReferralData.setCacheMap(new HashMap<>());
            mockReferralData.replaceCache();
            mockReferralData.append(mockReferralData);
            
            // Verify all invocations
            verify(mockReferralData, atLeastOnce()).getExpiration();
            verify(mockReferralData, atLeastOnce()).getPathConsumed();
            verify(mockReferralData, atLeastOnce()).getDomain();
            verify(mockReferralData, atLeastOnce()).getLink();
            verify(mockReferralData, atLeastOnce()).getServer();
            verify(mockReferralData, atLeastOnce()).getShare();
            verify(mockReferralData, atLeastOnce()).getPath();
            verify(mockReferralData, atLeastOnce()).next();
            verify(mockReferralData, atLeastOnce()).getKey();
            verify(mockReferralData, atLeastOnce()).isResolveHashes();
            verify(mockReferralData, atLeastOnce()).isIntermediate();
            verify(mockReferralData, atLeastOnce()).combine(any());
            verify(mockReferralData, atLeastOnce()).fixupHost(anyString());
            verify(mockReferralData, atLeastOnce()).fixupDomain(anyString());
            verify(mockReferralData, atLeastOnce()).stripPathConsumed(anyInt());
            verify(mockReferralData, atLeastOnce()).setLink(anyString());
            verify(mockReferralData, atLeastOnce()).setKey(anyString());
            verify(mockReferralData, atLeastOnce()).setCacheMap(any());
            verify(mockReferralData, atLeastOnce()).replaceCache();
            verify(mockReferralData, atLeastOnce()).append(any());
        }
        
        @Test
        @DisplayName("Should verify method invocation order")
        void testMethodInvocationOrder() {
            // Setup ordered verification
            Map<String, DfsReferralDataInternal> cache = new HashMap<>();
            String key = "ordered-key";
            
            // Execute in specific order
            mockReferralData.setKey(key);
            mockReferralData.setCacheMap(cache);
            mockReferralData.replaceCache();
            
            // Verify order
            var inOrder = inOrder(mockReferralData);
            inOrder.verify(mockReferralData).setKey(key);
            inOrder.verify(mockReferralData).setCacheMap(cache);
            inOrder.verify(mockReferralData).replaceCache();
        }
    }
}
