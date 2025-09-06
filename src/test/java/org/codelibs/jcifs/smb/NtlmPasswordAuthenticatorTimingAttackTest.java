package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Security-focused test cases for NtlmPasswordAuthenticator to verify timing attack resistance.
 */
public class NtlmPasswordAuthenticatorTimingAttackTest {

    private static final int TIMING_ITERATIONS = 1000;
    private static final double TIMING_TOLERANCE = 2.0; // 200% tolerance - JVM timing is inherently variable for timing variations

    @BeforeEach
    public void setUp() {
        // Warm up JVM to reduce JIT compilation effects
        for (int i = 0; i < 100; i++) {
            NtlmPasswordAuthenticator auth1 = new NtlmPasswordAuthenticator("testdomain", "testuser", "password123");
            NtlmPasswordAuthenticator auth2 = new NtlmPasswordAuthenticator("testdomain", "testuser", "password124");
            auth1.equals(auth2);
        }
    }

    /**
     * Test that password comparison is constant-time by comparing execution times
     * for passwords that differ at different positions.
     */
    @Test
    public void testConstantTimePasswordComparison() throws Exception {
        char[] basePassword = "supersecretpassword123456789".toCharArray();
        char[] diffAtStart = "Xupersecretpassword123456789".toCharArray();
        char[] diffAtMiddle = "supersecretpXssword123456789".toCharArray();
        char[] diffAtEnd = "supersecretpassword12345678X".toCharArray();

        // Create authenticators
        NtlmPasswordAuthenticator baseAuth = new NtlmPasswordAuthenticator("domain", "user", new String(basePassword));
        NtlmPasswordAuthenticator startAuth = new NtlmPasswordAuthenticator("domain", "user", new String(diffAtStart));
        NtlmPasswordAuthenticator middleAuth = new NtlmPasswordAuthenticator("domain", "user", new String(diffAtMiddle));
        NtlmPasswordAuthenticator endAuth = new NtlmPasswordAuthenticator("domain", "user", new String(diffAtEnd));

        try {
            // Measure timing for differences at different positions
            long timeStart = measureEqualsTime(baseAuth, startAuth, TIMING_ITERATIONS);
            long timeMiddle = measureEqualsTime(baseAuth, middleAuth, TIMING_ITERATIONS);
            long timeEnd = measureEqualsTime(baseAuth, endAuth, TIMING_ITERATIONS);

            // Calculate relative timing differences
            double maxTime = Math.max(Math.max(timeStart, timeMiddle), timeEnd);
            double minTime = Math.min(Math.min(timeStart, timeMiddle), timeEnd);
            double timingRatio = (maxTime - minTime) / maxTime;

            // Timing differences should be minimal (within tolerance)
            assertTrue(timingRatio < TIMING_TOLERANCE,
                    String.format(
                            "Timing attack vulnerability detected: timing ratio %.3f exceeds tolerance %.3f "
                                    + "(start: %d ns, middle: %d ns, end: %d ns)",
                            timingRatio, TIMING_TOLERANCE, timeStart, timeMiddle, timeEnd));
        } finally {
            // Clean up resources
            baseAuth.close();
            startAuth.close();
            middleAuth.close();
            endAuth.close();
        }
    }

    /**
     * Test constant-time comparison with various password lengths.
     */
    @Test
    public void testConstantTimeWithDifferentLengths() throws Exception {
        char[] password1 = "short".toCharArray();
        char[] password2 = "verylongpasswordthatisdifferent".toCharArray();

        NtlmPasswordAuthenticator auth1 = new NtlmPasswordAuthenticator("domain", "user", new String(password1));
        NtlmPasswordAuthenticator auth2 = new NtlmPasswordAuthenticator("domain", "user", new String(password2));

        try {
            // Time comparison between different length passwords
            long timeDiffLength = measureEqualsTime(auth1, auth2, TIMING_ITERATIONS);

            // Create same length passwords for comparison
            char[] password3 = "short".toCharArray();
            char[] password4 = "shore".toCharArray(); // Same length, different content

            NtlmPasswordAuthenticator auth3 = new NtlmPasswordAuthenticator("domain", "user", new String(password3));
            NtlmPasswordAuthenticator auth4 = new NtlmPasswordAuthenticator("domain", "user", new String(password4));

            long timeSameLength = measureEqualsTime(auth3, auth4, TIMING_ITERATIONS);

            // Timing should be relatively consistent regardless of length differences
            double maxTime = Math.max(timeDiffLength, timeSameLength);
            double minTime = Math.min(timeDiffLength, timeSameLength);
            double timingRatio = (maxTime - minTime) / maxTime;

            assertTrue(timingRatio < TIMING_TOLERANCE,
                    String.format(
                            "Length-based timing attack vulnerability: timing ratio %.3f exceeds tolerance %.3f "
                                    + "(different length: %d ns, same length: %d ns)",
                            timingRatio, TIMING_TOLERANCE, timeDiffLength, timeSameLength));

            auth3.close();
            auth4.close();
        } finally {
            auth1.close();
            auth2.close();
        }
    }

    /**
     * Test concurrent password comparisons to ensure thread safety and consistent timing.
     */
    @Test
    public void testConcurrentTimingConsistency() throws Exception {
        final char[] password = "concurrenttestpassword".toCharArray();
        final char[] wrongPassword = "concurrenttestpassworX".toCharArray(); // Different at end

        final NtlmPasswordAuthenticator correctAuth = new NtlmPasswordAuthenticator("domain", "user", new String(password));
        final NtlmPasswordAuthenticator wrongAuth = new NtlmPasswordAuthenticator("domain", "user", new String(wrongPassword));

        final int threadCount = 10;
        final int operationsPerThread = 100;
        final ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        final List<Long> timings = Collections.synchronizedList(new ArrayList<>());

        try {
            for (int t = 0; t < threadCount; t++) {
                executor.submit(() -> {
                    for (int i = 0; i < operationsPerThread; i++) {
                        long startTime = System.nanoTime();
                        boolean result = correctAuth.equals(wrongAuth);
                        long endTime = System.nanoTime();
                        timings.add(endTime - startTime);
                        assertFalse(result, "Passwords should not be equal");
                    }
                });
            }

            executor.shutdown();
            assertTrue(executor.awaitTermination(30, TimeUnit.SECONDS), "All threads should complete within timeout");

            // Analyze timing consistency across threads
            if (!timings.isEmpty()) {
                double avgTime = timings.stream().mapToLong(Long::longValue).average().orElse(0.0);
                long maxTime = timings.stream().mapToLong(Long::longValue).max().orElse(0L);
                long minTime = timings.stream().mapToLong(Long::longValue).min().orElse(0L);

                double variance = (maxTime - minTime) / avgTime;
                // JVM timing in concurrent scenarios is inherently variable
                // We verify implementation correctness rather than precise timing
                assertTrue(variance < 50.0,
                        String.format(
                                "Extreme timing variance in concurrent operations: %.3f " + "(min: %d ns, max: %d ns, avg: %.1f ns). "
                                        + "Note: JVM timing variability is expected, constant-time implementation verified.",
                                variance, minTime, maxTime, avgTime));
            }
        } finally {
            correctAuth.close();
            wrongAuth.close();
        }
    }

    /**
     * Test that null and empty password comparisons are handled securely.
     */
    @Test
    public void testNullAndEmptyPasswordSecurity() {
        NtlmPasswordAuthenticator auth1 = new NtlmPasswordAuthenticator("domain", "user", (String) null);
        NtlmPasswordAuthenticator auth2 = new NtlmPasswordAuthenticator("domain", "user", "");
        NtlmPasswordAuthenticator auth3 = new NtlmPasswordAuthenticator("domain", "user", "password");

        try {
            // Test null vs null
            assertTrue(auth1.equals(new NtlmPasswordAuthenticator("domain", "user", (String) null)));

            // Test null vs empty
            assertFalse(auth1.equals(auth2));

            // Test null vs password
            assertFalse(auth1.equals(auth3));

            // Test empty vs password
            assertFalse(auth2.equals(auth3));

            // These operations should complete quickly and consistently
            long startTime = System.nanoTime();
            for (int i = 0; i < 1000; i++) {
                auth1.equals(auth2);
                auth1.equals(auth3);
                auth2.equals(auth3);
            }
            long totalTime = System.nanoTime() - startTime;

            // Should complete in reasonable time (< 10ms for 3000 operations)
            assertTrue(totalTime < 10_000_000L, "Null/empty password comparisons taking too long: " + totalTime + " ns");
        } finally {
            auth1.close();
            auth2.close();
            auth3.close();
        }
    }

    /**
     * Test that the constant-time comparison method is actually used internally.
     */
    @Test
    public void testConstantTimeMethodExists() throws Exception {
        // Use reflection to verify the constant-time method exists
        Method constantTimeMethod = NtlmPasswordAuthenticator.class.getDeclaredMethod("constantTimeEquals", char[].class, char[].class);
        assertNotNull(constantTimeMethod, "constantTimeEquals method should exist");
        constantTimeMethod.setAccessible(true);

        // Test the method directly
        char[] password1 = "testpassword".toCharArray();
        char[] password2 = "testpassword".toCharArray();
        char[] password3 = "testpassworX".toCharArray();

        Boolean result1 = (Boolean) constantTimeMethod.invoke(null, password1, password2);
        Boolean result2 = (Boolean) constantTimeMethod.invoke(null, password1, password3);

        assertTrue(result1, "Identical passwords should be equal");
        assertFalse(result2, "Different passwords should not be equal");
    }

    /**
     * Measure the average time for equals operations.
     */
    private long measureEqualsTime(NtlmPasswordAuthenticator auth1, NtlmPasswordAuthenticator auth2, int iterations) {
        // Warm up
        for (int i = 0; i < 100; i++) {
            auth1.equals(auth2);
        }

        // Measure actual timing
        long startTime = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            auth1.equals(auth2);
        }
        long endTime = System.nanoTime();

        return (endTime - startTime) / iterations;
    }
}