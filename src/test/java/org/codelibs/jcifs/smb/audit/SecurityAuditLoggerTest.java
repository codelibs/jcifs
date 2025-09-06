/*
 * © 2025 org.codelibs.jcifs.smb Project
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.codelibs.jcifs.smb.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.codelibs.jcifs.smb.audit.SecurityAuditLogger.EventType;
import org.codelibs.jcifs.smb.audit.SecurityAuditLogger.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test class for SecurityAuditLogger
 */
public class SecurityAuditLoggerTest {

    private SecurityAuditLogger logger;

    @BeforeEach
    void setUp() {
        logger = SecurityAuditLogger.getInstance();
        logger.resetStatistics();
        logger.setJsonLoggingEnabled(false);
        logger.setSensitiveDataMaskingEnabled(true);
    }

    @Test
    @DisplayName("Test singleton instance")
    void testSingletonInstance() {
        SecurityAuditLogger logger1 = SecurityAuditLogger.getInstance();
        SecurityAuditLogger logger2 = SecurityAuditLogger.getInstance();
        assertSame(logger1, logger2, "SecurityAuditLogger should be a singleton");
    }

    @Test
    @DisplayName("Test log authentication success")
    void testLogAuthentication() {
        logger.logAuthentication(true, "testuser", "DOMAIN", "192.168.1.1");

        Map<EventType, Long> stats = logger.getStatistics();
        assertEquals(Long.valueOf(1), stats.get(EventType.AUTHENTICATION_SUCCESS), "Should have 1 authentication event");
    }

    @Test
    @DisplayName("Test log authentication failure")
    void testLogAuthenticationFailure() {
        logger.logAuthentication(false, "testuser", "DOMAIN", "192.168.1.1");

        Map<EventType, Long> stats = logger.getStatistics();
        assertEquals(Long.valueOf(1), stats.get(EventType.AUTHENTICATION_FAILURE), "Should have 1 authentication failure event");
    }

    @Test
    @DisplayName("Test log file access")
    void testLogFileAccess() {
        logger.logFileAccess("READ", "/path/to/file.txt", true, "testuser");

        Map<EventType, Long> stats = logger.getStatistics();
        assertEquals(Long.valueOf(1), stats.get(EventType.FILE_ACCESS), "Should have 1 file access event");
    }

    @Test
    @DisplayName("Test log encryption")
    void testLogEncryption() {
        logger.logEncryption(true, "AES-128-GCM", "SMB3.1.1");

        Map<EventType, Long> stats = logger.getStatistics();
        assertEquals(Long.valueOf(1), stats.get(EventType.ENCRYPTION_ENABLED), "Should have 1 encryption event");
    }

    @Test
    @DisplayName("Test log security violation")
    void testLogSecurityViolation() {
        Map<String, Object> context = new HashMap<>();
        context.put("sourceIP", "192.168.1.100");
        context.put("attemptCount", 5);

        logger.logSecurityViolation("Multiple failed authentication attempts", context);

        Map<EventType, Long> stats = logger.getStatistics();
        assertEquals(Long.valueOf(1), stats.get(EventType.SECURITY_VIOLATION), "Should have 1 security violation event");
    }

    @Test
    @DisplayName("Test log event")
    void testLogEvent() {
        Map<String, Object> context = new HashMap<>();
        context.put("key1", "value1");
        context.put("key2", "value2");

        logger.logEvent(EventType.CONFIGURATION_CHANGE, Severity.INFO, "Configuration changed", context);

        Map<EventType, Long> stats = logger.getStatistics();
        assertEquals(Long.valueOf(1), stats.get(EventType.CONFIGURATION_CHANGE), "Should have 1 configuration event");
    }

    @Test
    @DisplayName("Test statistics accumulation")
    void testStatisticsAccumulation() {
        logger.logAuthentication(true, "user1", "DOMAIN", "192.168.1.1");
        logger.logAuthentication(false, "user2", "DOMAIN", "192.168.1.2");
        logger.logFileAccess("WRITE", "/file.txt", true, "user1");

        Map<EventType, Long> stats = logger.getStatistics();
        assertEquals(Long.valueOf(1), stats.get(EventType.AUTHENTICATION_SUCCESS), "Should have 1 authentication success event");
        assertEquals(Long.valueOf(1), stats.get(EventType.AUTHENTICATION_FAILURE), "Should have 1 authentication failure event");
        assertEquals(Long.valueOf(1), stats.get(EventType.FILE_ACCESS), "Should have 1 file access event");
    }

    @Test
    @DisplayName("Test reset statistics")
    void testResetStatistics() {
        logger.logAuthentication(true, "user", "DOMAIN", "192.168.1.1");
        logger.logFileAccess("READ", "/file.txt", true, "user");

        Map<EventType, Long> statsBefore = logger.getStatistics();
        assertTrue(statsBefore.get(EventType.AUTHENTICATION_SUCCESS) > 0, "Should have authentication events before reset");
        assertTrue(statsBefore.get(EventType.FILE_ACCESS) > 0, "Should have file access events before reset");

        logger.resetStatistics();

        Map<EventType, Long> statsAfter = logger.getStatistics();
        // After reset, all counters should be 0
        for (Long count : statsAfter.values()) {
            assertEquals(Long.valueOf(0), count, "All statistics should be 0 after reset");
        }
    }

    @Test
    @DisplayName("Test JSON logging toggle")
    void testJsonLoggingToggle() {
        logger.setJsonLoggingEnabled(true);
        logger.logAuthentication(true, "user", "DOMAIN", "192.168.1.1");

        logger.setJsonLoggingEnabled(false);
        logger.logAuthentication(true, "user2", "DOMAIN", "192.168.1.2");

        // Verify that both events were logged
        Map<EventType, Long> stats = logger.getStatistics();
        assertEquals(Long.valueOf(2), stats.get(EventType.AUTHENTICATION_SUCCESS), "Should have 2 authentication success events");
    }

    @Test
    @DisplayName("Test sensitive data masking")
    void testSensitiveDataMasking() {
        logger.setSensitiveDataMaskingEnabled(true);

        Map<String, Object> context = new HashMap<>();
        context.put("password", "secretpassword123");
        context.put("sessionId", "abc123def456");
        context.put("username", "john.doe@example.com");

        logger.logEvent(EventType.AUTHENTICATION_SUCCESS, Severity.INFO, "Login attempt", context);

        // The test verifies that the logger runs without errors when masking is enabled
        Map<EventType, Long> stats = logger.getStatistics();
        assertEquals(Long.valueOf(1), stats.get(EventType.AUTHENTICATION_SUCCESS), "Should have 1 authentication event");
    }

    @Test
    @DisplayName("Test stack trace inclusion")
    void testStackTraceInclusion() {
        logger.setIncludeStackTrace(true);

        Map<String, Object> context = new HashMap<>();
        context.put("error", "Test error");

        logger.logSecurityViolation("Test violation with stack trace", context);

        logger.setIncludeStackTrace(false);
        logger.logSecurityViolation("Test violation without stack trace", context);

        Map<EventType, Long> stats = logger.getStatistics();
        assertEquals(Long.valueOf(2), stats.get(EventType.SECURITY_VIOLATION), "Should have 2 security violation events");
    }

    @Test
    @DisplayName("Test concurrent logging")
    void testConcurrentLogging() throws InterruptedException {
        int threadCount = 10;
        int eventsPerThread = 100;
        Thread[] threads = new Thread[threadCount];

        for (int i = 0; i < threadCount; i++) {
            final int threadId = i;
            threads[i] = new Thread(() -> {
                for (int j = 0; j < eventsPerThread; j++) {
                    logger.logAuthentication(true, "user" + threadId, "DOMAIN", "192.168.1." + threadId);
                }
            });
            threads[i].start();
        }

        for (Thread thread : threads) {
            thread.join();
        }

        Map<EventType, Long> stats = logger.getStatistics();
        assertEquals(Long.valueOf(threadCount * eventsPerThread), stats.get(EventType.AUTHENTICATION_SUCCESS),
                "Should have correct total number of events");
    }
}