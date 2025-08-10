/*
 * Copyright 2021 CodeLibs Project and the Others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */
package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.HashMap;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.smb1.smb1.NtlmPasswordAuthentication;
import jcifs.smb1.smb1.SmbAuthException;
import jcifs.smb1.UniAddress;
import jcifs.smb1.util.LogStream;

@ExtendWith(MockitoExtension.class)
class DfsTest {

    @Mock
    private NtlmPasswordAuthentication auth;

    @Mock
    private SmbTransport smbTransport;

    @Mock
    private UniAddress uniAddress;

    @Mock
    private DfsReferral dfsReferral;

    private Dfs dfs;

    private MockedStatic<LogStream> logStreamMockedStatic;
    private MockedStatic<UniAddress> uniAddressMockedStatic;
    private MockedStatic<SmbTransport> smbTransportMockedStatic;

    @BeforeEach
    void setUp() {
        dfs = new Dfs();
        // Mock static methods
        logStreamMockedStatic = mockStatic(LogStream.class);
        when(LogStream.getInstance()).thenReturn(mock(LogStream.class));
        uniAddressMockedStatic = mockStatic(UniAddress.class);
        smbTransportMockedStatic = mockStatic(SmbTransport.class);
    }

    @AfterEach
    void tearDown() {
        logStreamMockedStatic.close();
        uniAddressMockedStatic.close();
        smbTransportMockedStatic.close();
    }

    @Test
    void testCacheEntry() {
        // Test with a specific TTL
        long ttl = 600; // 10 minutes
        Dfs.CacheEntry cacheEntry = new Dfs.CacheEntry(ttl);
        long expectedExpiration = System.currentTimeMillis() + ttl * 1000L;
        assertTrue(cacheEntry.expiration >= expectedExpiration - 100 && cacheEntry.expiration <= expectedExpiration + 100);
        assertNotNull(cacheEntry.map);

        // Test with TTL = 0, should use default TTL
        Dfs.CacheEntry cacheEntryDefault = new Dfs.CacheEntry(0);
        long expectedExpirationDefault = System.currentTimeMillis() + Dfs.TTL * 1000L;
        assertTrue(cacheEntryDefault.expiration >= expectedExpirationDefault - 100 && cacheEntryDefault.expiration <= expectedExpirationDefault + 100);
    }

    @Test
    void testGetTrustedDomains_Disabled() throws SmbAuthException {
        assertNull(dfs.getTrustedDomains(auth));
    }

    @Test
    void testGetTrustedDomains_Cached() throws SmbAuthException {
        Dfs.CacheEntry cacheEntry = new Dfs.CacheEntry(300);
        HashMap<String, HashMap> trustedDomains = new HashMap<>();
        trustedDomains.put("domain.com", new HashMap());
        cacheEntry.map = trustedDomains;
        dfs._domains = cacheEntry;

        assertEquals(trustedDomains, dfs.getTrustedDomains(auth));
    }

    @Test
    void testGetTrustedDomains_ExpiredCache() throws IOException, SmbAuthException {
        // Set up an expired cache entry
        Dfs.CacheEntry expiredEntry = new Dfs.CacheEntry(-1); // Expired
        dfs._domains = expiredEntry;

        when(auth.getDomain()).thenReturn("domain.com");
        when(UniAddress.getByName(anyString(), any(boolean.class))).thenReturn(uniAddress);
        when(SmbTransport.getSmbTransport(any(UniAddress.class), anyInt())).thenReturn(smbTransport);
        when(smbTransport.getDfsReferrals(any(NtlmPasswordAuthentication.class), anyString(), anyInt())).thenReturn(null);

        assertNull(dfs.getTrustedDomains(auth));
    }

    @Test
    void testGetTrustedDomains_Success() throws IOException, SmbAuthException {
        when(auth.getDomain()).thenReturn("domain.com");
        when(UniAddress.getByName("domain.com", true)).thenReturn(uniAddress);
        when(SmbTransport.getSmbTransport(uniAddress, 0)).thenReturn(smbTransport);

        DfsReferral referral = new DfsReferral();
        referral.server = "server1.domain.com";
        referral.next = referral; // Circular list
        when(smbTransport.getDfsReferrals(auth, "", 0)).thenReturn(referral);

        HashMap<String, HashMap> trustedDomains = dfs.getTrustedDomains(auth);
        assertNotNull(trustedDomains);
        assertTrue(trustedDomains.containsKey("server1.domain.com"));
    }
    
    @Test
    void testIsTrustedDomain() throws SmbAuthException {
        Dfs.CacheEntry cacheEntry = new Dfs.CacheEntry(300);
        HashMap<String, HashMap> trustedDomains = new HashMap<>();
        trustedDomains.put("domain.com", new HashMap());
        cacheEntry.map = trustedDomains;
        dfs._domains = cacheEntry;

        assertTrue(dfs.isTrustedDomain("domain.com", auth));
        assertFalse(dfs.isTrustedDomain("otherdomain.com", auth));
    }

    @Test
    void testGetDc_Disabled() throws SmbAuthException {
        assertNull(dfs.getDc("domain.com", auth));
    }

    @Test
    void testGetDc_Success() throws IOException, SmbAuthException {
        when(UniAddress.getByName("domain.com", true)).thenReturn(uniAddress);
        when(SmbTransport.getSmbTransport(uniAddress, 0)).thenReturn(smbTransport);

        DfsReferral referral = new DfsReferral();
        referral.server = "dc1.domain.com";
        referral.next = referral;
        when(smbTransport.getDfsReferrals(auth, "\\domain.com", 1)).thenReturn(referral);

        UniAddress dcAddress = mock(UniAddress.class);
        when(UniAddress.getByName("dc1.domain.com")).thenReturn(dcAddress);
        SmbTransport dcTransport = mock(SmbTransport.class);
        when(SmbTransport.getSmbTransport(dcAddress, 0)).thenReturn(dcTransport);

        assertEquals(dcTransport, dfs.getDc("domain.com", auth));
    }

    @Test
    void testGetReferral_Disabled() throws SmbAuthException {
        assertNull(dfs.getReferral(smbTransport, "domain", "root", "path", auth));
    }

    @Test
    void testGetReferral_Success() throws IOException, SmbAuthException {
        String domain = "domain.com";
        String root = "share";
        String path = "\\folder";
        String fullPath = domain + "\\" + root + path;

        when(smbTransport.getDfsReferrals(auth, fullPath, 0)).thenReturn(dfsReferral);

        assertEquals(dfsReferral, dfs.getReferral(smbTransport, domain, root, path, auth));
    }

    @Test
    void testResolve_Disabled() throws SmbAuthException {
        assertNull(dfs.resolve("domain", "root", "path", auth));
    }

    @Test
    void testResolve_IpcShare() throws SmbAuthException {
        assertNull(dfs.resolve("domain", "IPC$", "path", auth));
    }

    @Test
    void testInsert() {
        String path = "\\server\\share\\folder";
        DfsReferral dr = new DfsReferral();
        dr.pathConsumed = path.length();

        dfs.insert(path, dr);

        assertNotNull(dfs.referrals);
        assertFalse(dfs.referrals.map.isEmpty());
        String key = "\\server\\share\\folder";
        assertTrue(dfs.referrals.map.containsKey(key.toLowerCase()));
    }
    
    @Test
    void testInsert_WithTrailingSlash() {
        String path = "\\server\\share\\folder\\";
        DfsReferral dr = new DfsReferral();
        dr.pathConsumed = path.length();

        dfs.insert(path, dr);

        assertNotNull(dfs.referrals);
        assertFalse(dfs.referrals.map.isEmpty());
        String key = "\\server\\share\\folder"; // Trailing slash should be removed
        assertTrue(dfs.referrals.map.containsKey(key.toLowerCase()));
    }
}
