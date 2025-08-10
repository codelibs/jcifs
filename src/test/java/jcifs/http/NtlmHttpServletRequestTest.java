/*
 * Copyright 2025 Shinsuke Ogawa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package jcifs.http;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link NtlmHttpServletRequest}.
 */
@ExtendWith(MockitoExtension.class)
class NtlmHttpServletRequestTest {

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private Principal mockPrincipal;

    private NtlmHttpServletRequest ntlmRequest;

    @BeforeEach
    void setUp() {
        // Create a new NtlmHttpServletRequest with mocked dependencies before each test
        ntlmRequest = new NtlmHttpServletRequest(mockRequest, mockPrincipal);
    }

    /**
     * Test method for {@link NtlmHttpServletRequest#getRemoteUser()}.
     * Verifies that the method returns the name of the principal.
     */
    @Test
    void testGetRemoteUser() {
        // Arrange: Define the expected user name from the principal
        String expectedUserName = "testUser";
        when(mockPrincipal.getName()).thenReturn(expectedUserName);

        // Act: Call the method under test
        String actualUserName = ntlmRequest.getRemoteUser();

        // Assert: Verify that the returned user name is the expected one
        assertEquals(expectedUserName, actualUserName, "getRemoteUser should return the principal's name.");
    }

    /**
     * Test method for {@link NtlmHttpServletRequest#getUserPrincipal()}.
     * Verifies that the method returns the correct principal object.
     */
    @Test
    void testGetUserPrincipal() {
        // Act: Call the method under test
        Principal actualPrincipal = ntlmRequest.getUserPrincipal();

        // Assert: Verify that the returned principal is the same as the one provided in the constructor
        assertSame(mockPrincipal, actualPrincipal, "getUserPrincipal should return the principal object.");
    }

    /**
     * Test method for {@link NtlmHttpServletRequest#getAuthType()}.
     * Verifies that the method always returns "NTLM".
     */
    @Test
    void testGetAuthType() {
        // Arrange: Define the expected authentication type
        String expectedAuthType = "NTLM";

        // Act: Call the method under test
        String actualAuthType = ntlmRequest.getAuthType();

        // Assert: Verify that the returned authentication type is "NTLM"
        assertEquals(expectedAuthType, actualAuthType, "getAuthType should always return 'NTLM'.");
    }
}
