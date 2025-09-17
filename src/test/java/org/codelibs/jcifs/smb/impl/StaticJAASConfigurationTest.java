package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for StaticJAASConfiguration.
 *
 * Coverage goals:
 * - Happy path with default and custom options.
 * - Null/empty/ignored name parameter handling.
 * - Null options edge case.
 * - Repeated calls equivalence and instance separation.
 * - Interaction check that passed options are not mutated.
 */
@ExtendWith(MockitoExtension.class)
class StaticJAASConfigurationTest {

    // Constants used in assertions
    private static final String EXPECTED_LOGIN_MODULE = "com.sun.security.auth.module.Krb5LoginModule";

    @Test
    @DisplayName("Default constructor yields REQUIRED Krb5 entry with empty options")
    void defaultConstructor_producesRequiredKrb5EntryWithEmptyOptions() {
        // Arrange
        StaticJAASConfiguration cfg = new StaticJAASConfiguration();

        // Act
        AppConfigurationEntry[] entries = cfg.getAppConfigurationEntry("ignored");

        // Assert
        assertNotNull(entries, "Entries array should not be null");
        assertEquals(1, entries.length, "Exactly one entry is expected");
        AppConfigurationEntry e = entries[0];
        assertNotNull(e, "Entry should not be null");
        assertEquals(EXPECTED_LOGIN_MODULE, e.getLoginModuleName(), "Login module should be Kerberos");
        assertEquals(LoginModuleControlFlag.REQUIRED, e.getControlFlag(), "Control flag should be REQUIRED");
        assertNotNull(e.getOptions(), "Options map should not be null");
        assertTrue(e.getOptions().isEmpty(), "Default options should be empty");
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = { "", "svc/http@EXAMPLE.COM" })
    @DisplayName("Name parameter is ignored (null/empty/arbitrary)")
    void nameParameter_isIgnoredAndDoesNotAffectResult(String name) {
        // Arrange
        StaticJAASConfiguration cfg = new StaticJAASConfiguration();

        // Act
        AppConfigurationEntry[] entries = cfg.getAppConfigurationEntry(name);

        // Assert
        assertNotNull(entries, "Entries array should not be null");
        assertEquals(1, entries.length, "Exactly one entry is expected");
        AppConfigurationEntry e = entries[0];
        assertEquals(EXPECTED_LOGIN_MODULE, e.getLoginModuleName(), "Login module should be Kerberos");
        assertEquals(LoginModuleControlFlag.REQUIRED, e.getControlFlag(), "Control flag should be REQUIRED");
    }

    @Test
    @DisplayName("Custom options are propagated to the AppConfigurationEntry")
    void customOptions_arePropagated() {
        // Arrange
        Map<String, Object> opts = new HashMap<>();
        opts.put("useKeyTab", "true");
        opts.put("storeKey", "true");
        opts.put("principal", "user@EXAMPLE.COM");
        StaticJAASConfiguration cfg = new StaticJAASConfiguration(opts);

        // Act
        AppConfigurationEntry[] entries = cfg.getAppConfigurationEntry("any");
        AppConfigurationEntry e = entries[0];
        Map<String, ?> returned = e.getOptions();

        // Assert
        assertNotNull(returned, "Returned options should not be null");
        assertEquals("true", returned.get("useKeyTab"));
        assertEquals("true", returned.get("storeKey"));
        assertEquals("user@EXAMPLE.COM", returned.get("principal"));
        // Ensure no unexpected extra options
        assertEquals(3, returned.size(), "Only provided options are expected");
    }

    @Test
    @DisplayName("Null options cause IllegalArgumentException when retrieving entries (JAAS requires non-null options)")
    void nullOptions_throwOnAccess() {
        // Arrange
        StaticJAASConfiguration cfg = new StaticJAASConfiguration(null);

        // Act + Assert
        assertThrows(IllegalArgumentException.class, () -> cfg.getAppConfigurationEntry("any"),
                "JAAS AppConfigurationEntry requires non-null options");
    }

    @Test
    @DisplayName("Repeated calls return distinct entries with equivalent semantics")
    void repeatedCalls_distinctEntriesSameSemantics() {
        // Arrange
        Map<String, Object> opts = new HashMap<>();
        opts.put("doNotPrompt", "true");
        StaticJAASConfiguration cfg = new StaticJAASConfiguration(opts);

        // Act
        AppConfigurationEntry[] a1 = cfg.getAppConfigurationEntry("x");
        AppConfigurationEntry[] a2 = cfg.getAppConfigurationEntry("y");

        // Assert
        assertNotSame(a1, a2, "Arrays should be different instances");
        assertEquals(1, a1.length);
        assertEquals(1, a2.length);

        AppConfigurationEntry e1 = a1[0];
        AppConfigurationEntry e2 = a2[0];

        assertNotSame(e1, e2, "Entries should be different instances");
        assertEquals(EXPECTED_LOGIN_MODULE, e1.getLoginModuleName());
        assertEquals(EXPECTED_LOGIN_MODULE, e2.getLoginModuleName());
        assertEquals(LoginModuleControlFlag.REQUIRED, e1.getControlFlag());
        assertEquals(LoginModuleControlFlag.REQUIRED, e2.getControlFlag());
        assertEquals(e1.getOptions(), e2.getOptions(), "Options content should be equivalent across calls");
    }

    @Test
    @DisplayName("Options map is not mutated by configuration (verify no writes)")
    void optionsMap_notMutated_verifyNoWrites() {
        // Arrange: create a regular map first, then spy on it
        Map<String, Object> originalMap = new HashMap<>();
        originalMap.put("refreshKrb5Config", "true");

        @SuppressWarnings("unchecked")
        Map<String, Object> spyOpts = spy(originalMap);

        // Reset the spy to clear any prior invocations from setup
        reset(spyOpts);

        StaticJAASConfiguration cfg = new StaticJAASConfiguration(spyOpts);

        // Act
        AppConfigurationEntry[] entries = cfg.getAppConfigurationEntry("ignored");
        Map<String, ?> returned = entries[0].getOptions();

        // Assert: sanity check and verify that no mutating calls were made after construction
        assertEquals("true", returned.get("refreshKrb5Config"));
        verify(spyOpts, never()).put(any(), any());
        verify(spyOpts, never()).remove(any());
        verify(spyOpts, never()).clear();
    }
}
