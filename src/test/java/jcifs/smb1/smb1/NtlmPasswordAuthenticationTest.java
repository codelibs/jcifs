/*
 * Copyright 2025 CodeLibs Project and the Others.
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

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

import jcifs.smb1.smb1.NtlmPasswordAuthentication;

/**
 * Tests for NtlmPasswordAuthentication class.
 */
class NtlmPasswordAuthenticationTest {

    private static String originalLmCompatibility;

    @BeforeAll
    static void setUpClass() {
        // Save original property
        originalLmCompatibility = System.getProperty("jcifs.smb1.smb.lmCompatibility");
        // Set default for tests
        jcifs.smb1.Config.setProperty("jcifs.smb1.smb.lmCompatibility", "3");
    }

    @AfterAll
    static void tearDownClass() {
        // Restore original property
        if (originalLmCompatibility != null) {
            jcifs.smb1.Config.setProperty("jcifs.smb1.smb.lmCompatibility", originalLmCompatibility);
        } else {
            System.clearProperty("jcifs.smb1.smb.lmCompatibility");
        }
    }

    // Test constructor with domain, username, and password
    @Test
    void testConstructorWithDomainUsernamePassword() {
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication("DOMAIN", "user", "password");
        assertEquals("DOMAIN", auth.getDomain());
        assertEquals("user", auth.getUsername());
        assertEquals("password", auth.getPassword());
    }

    // Test constructor with user info string
    @Test
    void testConstructorWithUserInfo() {
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication("DOMAIN;user:password");
        assertEquals("DOMAIN", auth.getDomain());
        assertEquals("user", auth.getUsername());
        assertEquals("password", auth.getPassword());
    }
    
    // Test constructor with user info string without domain
    @Test
    void testConstructorWithUserInfoNoDomain() {
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication("user:password");
        assertNotNull(auth.getDomain()); // Should fall back to default
        assertEquals("user", auth.getUsername());
        assertEquals("password", auth.getPassword());
    }

    // Test constructor with user info string without password
    @Test
    void testConstructorWithUserInfoNoPassword() {
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication("DOMAIN;user");
        assertEquals("DOMAIN", auth.getDomain());
        assertEquals("user", auth.getUsername());
        assertNotNull(auth.getPassword()); // Should fall back to default
    }

    // Test constructor with external hashes
    @Test
    void testConstructorWithExternalHashes() {
        byte[] challenge = new byte[8];
        byte[] ansiHash = new byte[24];
        byte[] unicodeHash = new byte[24];
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication("DOMAIN", "user", challenge, ansiHash, unicodeHash);
        assertEquals("DOMAIN", auth.getDomain());
        assertEquals("user", auth.getUsername());
        assertNull(auth.getPassword());
        assertTrue(auth.hashesExternal);
        assertArrayEquals(ansiHash, auth.getAnsiHash(challenge));
        assertArrayEquals(unicodeHash, auth.getUnicodeHash(challenge));
    }

    // Test getName method
    @Test
    void testGetName() {
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication("DOMAIN", "user", "password");
        assertEquals("DOMAIN\\user", auth.getName());
    }
    
    // Test getName method with default domain
    @Test
    void testGetNameWithDefaultDomain() {
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication("?", "user", "password");
        assertEquals("user", auth.getName());
    }

    // Test equals method
    @Test
    void testEquals() {
        NtlmPasswordAuthentication auth1 = new NtlmPasswordAuthentication("DOMAIN", "user", "password");
        NtlmPasswordAuthentication auth2 = new NtlmPasswordAuthentication("DOMAIN", "user", "password");
        NtlmPasswordAuthentication auth3 = new NtlmPasswordAuthentication("DOMAIN", "user", "different_password");
        NtlmPasswordAuthentication auth4 = new NtlmPasswordAuthentication("DIFFERENT_DOMAIN", "user", "password");

        assertEquals(auth1, auth2);
        assertNotEquals(auth1, auth3);
        assertNotEquals(auth1, auth4);
        assertNotEquals(auth1, new Object());
    }

    // Test hashCode method
    @Test
    void testHashCode() {
        NtlmPasswordAuthentication auth1 = new NtlmPasswordAuthentication("DOMAIN", "user", "password");
        NtlmPasswordAuthentication auth2 = new NtlmPasswordAuthentication("DOMAIN", "user", "password");
        assertEquals(auth1.hashCode(), auth2.hashCode());
    }

    // Test getPreNTLMResponse
    @Test
    void testGetPreNTLMResponse() {
        byte[] challenge = {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] response = NtlmPasswordAuthentication.getPreNTLMResponse("password", challenge);
        assertNotNull(response);
        assertEquals(24, response.length);
    }

    // Test getNTLMResponse
    @Test
    void testGetNTLMResponse() {
        byte[] challenge = {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] response = NtlmPasswordAuthentication.getNTLMResponse("password", challenge);
        assertNotNull(response);
        assertEquals(24, response.length);
    }

    // Test getLMv2Response
    @Test
    void testGetLMv2Response() {
        byte[] challenge = {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] clientChallenge = {9, 10, 11, 12, 13, 14, 15, 16};
        byte[] response = NtlmPasswordAuthentication.getLMv2Response("DOMAIN", "user", "password", challenge, clientChallenge);
        assertNotNull(response);
        assertEquals(24, response.length);
    }

    // Test getNTLM2Response
    @Test
    void testGetNTLM2Response() {
        byte[] nTOWFv1 = NtlmPasswordAuthentication.nTOWFv1("password");
        byte[] serverChallenge = {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] clientChallenge = {9, 10, 11, 12, 13, 14, 15, 16};
        byte[] response = NtlmPasswordAuthentication.getNTLM2Response(nTOWFv1, serverChallenge, clientChallenge);
        assertNotNull(response);
        assertEquals(24, response.length);
    }

    // Test nTOWFv1
    @Test
    void testNTOWFv1() {
        byte[] hash = NtlmPasswordAuthentication.nTOWFv1("password");
        assertNotNull(hash);
        assertEquals(16, hash.length);
    }
    
    // Test nTOWFv2
    @Test
    void testNTOWFv2() {
        byte[] hash = NtlmPasswordAuthentication.nTOWFv2("DOMAIN", "user", "password");
        assertNotNull(hash);
        assertEquals(16, hash.length);
    }

    // Test unescape method
    @ParameterizedTest
    @CsvSource({
            "'test%20string', 'test string'",
            "'test%25string', 'test%string'",
            "'test', 'test'",
            "'' , ''"
    })
    void testUnescape(String input, String expected) throws Exception {
        assertEquals(expected, NtlmPasswordAuthentication.unescape(input));
    }

    // Test getAnsiHash always returns 24 bytes regardless of lmCompatibility
    @Test
    void testGetAnsiHashAlwaysReturns24Bytes() {
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication("DOMAIN", "user", "password");
        byte[] challenge = {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] hash = auth.getAnsiHash(challenge);
        assertNotNull(hash);
        // getAnsiHash always returns 24 bytes for all lmCompatibility levels
        // (getPreNTLMResponse, getNTLMResponse, or getLMv2Response all return 24 bytes)
        assertEquals(24, hash.length);
    }

    // Test getUnicodeHash behavior based on static LM_COMPATIBILITY setting
    @Test
    void testGetUnicodeHashWithDefaultLmCompatibility() {
        // With default lmCompatibility=3, getUnicodeHash returns empty array for NTLMv2
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication("DOMAIN", "user", "password");
        byte[] challenge = {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] hash = auth.getUnicodeHash(challenge);
        assertNotNull(hash);
        // For lmCompatibility 3,4,5 (NTLMv2), returns empty array
        assertEquals(0, hash.length);
    }
    
    // Test that changing lmCompatibility at runtime doesn't affect already loaded static value
    @ParameterizedTest
    @ValueSource(strings = {"0", "1", "2", "3", "4", "5"})
    void testLmCompatibilityStaticInitialization(String lmCompatibility) {
        // Attempt to change the property (won't affect static final LM_COMPATIBILITY)
        jcifs.smb1.Config.setProperty("jcifs.smb1.smb.lmCompatibility", lmCompatibility);
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication("DOMAIN", "user", "password");
        byte[] challenge = {1, 2, 3, 4, 5, 6, 7, 8};
        
        // Behavior is determined by static initialization, not runtime config
        byte[] unicodeHash = auth.getUnicodeHash(challenge);
        byte[] ansiHash = auth.getAnsiHash(challenge);
        
        // Unicode hash returns empty array due to static LM_COMPATIBILITY=3
        assertEquals(0, unicodeHash.length);
        // ANSI hash always returns 24 bytes
        assertEquals(24, ansiHash.length);
    }
    
    // Test ANONYMOUS constant
    @Test
    void testAnonymousConstant() {
        assertNotNull(NtlmPasswordAuthentication.ANONYMOUS);
        assertEquals("", NtlmPasswordAuthentication.ANONYMOUS.getDomain());
        assertEquals("", NtlmPasswordAuthentication.ANONYMOUS.getUsername());
        assertEquals("", NtlmPasswordAuthentication.ANONYMOUS.getPassword());
    }
}
