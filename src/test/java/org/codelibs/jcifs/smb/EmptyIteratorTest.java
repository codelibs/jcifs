package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Iterator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive test suite for EmptyIterator class.
 * Tests the implementation of CloseableIterator for empty collections.
 */
@DisplayName("EmptyIterator Tests")
class EmptyIteratorTest extends BaseTest {

    private EmptyIterator emptyIterator;

    @BeforeEach
    void setUp() {
        emptyIterator = new EmptyIterator();
    }

    @Test
    @DisplayName("EmptyIterator should implement CloseableIterator interface")
    void testInterfaceImplementation() {
        // Then
        assertTrue(emptyIterator instanceof CloseableIterator, "Should implement CloseableIterator");
        assertTrue(emptyIterator instanceof Iterator, "Should implement Iterator");
        assertTrue(emptyIterator instanceof AutoCloseable, "Should implement AutoCloseable");
    }

    @Test
    @DisplayName("hasNext should always return false")
    void testHasNextAlwaysReturnsFalse() {
        // When & Then
        assertFalse(emptyIterator.hasNext(), "hasNext should return false");
        assertFalse(emptyIterator.hasNext(), "hasNext should consistently return false");
        assertFalse(emptyIterator.hasNext(), "hasNext should always return false on repeated calls");
    }

    @Test
    @DisplayName("next should return null")
    void testNextReturnsNull() {
        // When
        SmbResource result = emptyIterator.next();

        // Then
        assertNull(result, "next() should return null for empty iterator");
    }

    @Test
    @DisplayName("next should not throw NoSuchElementException")
    void testNextDoesNotThrowException() {
        // When & Then
        assertDoesNotThrow(() -> {
            emptyIterator.next();
            emptyIterator.next();
            emptyIterator.next();
        }, "next() should not throw NoSuchElementException");
    }

    @Test
    @DisplayName("close should not throw any exception")
    void testCloseDoesNotThrowException() {
        // When & Then
        assertDoesNotThrow(() -> {
            try {
                emptyIterator.close();
            } catch (CIFSException e) {
                throw new RuntimeException(e);
            }
        }, "close() should not throw any exception");
    }

    @Test
    @DisplayName("remove should not throw any exception")
    void testRemoveDoesNotThrowException() {
        // When & Then
        assertDoesNotThrow(() -> {
            emptyIterator.remove();
        }, "remove() should not throw any exception");
    }

    @Test
    @DisplayName("EmptyIterator should behave consistently across multiple calls")
    void testConsistentBehavior() {
        // When & Then - test multiple sequential calls
        for (int i = 0; i < 10; i++) {
            assertFalse(emptyIterator.hasNext(), "hasNext should consistently return false");
            assertNull(emptyIterator.next(), "next should consistently return null");
        }
    }

    @RepeatedTest(5)
    @DisplayName("EmptyIterator should behave consistently across multiple instances")
    void testMultipleInstanceConsistency() {
        // Given & When & Then
        assertDoesNotThrow(() -> {
            try (EmptyIterator iterator1 = new EmptyIterator();
                    EmptyIterator iterator2 = new EmptyIterator();
                    EmptyIterator iterator3 = new EmptyIterator()) {
                assertFalse(iterator1.hasNext(), "First instance should have no elements");
                assertFalse(iterator2.hasNext(), "Second instance should have no elements");
                assertFalse(iterator3.hasNext(), "Third instance should have no elements");

                assertNull(iterator1.next(), "First instance next() should return null");
                assertNull(iterator2.next(), "Second instance next() should return null");
                assertNull(iterator3.next(), "Third instance next() should return null");
            } catch (CIFSException e) {
                throw new RuntimeException(e);
            }
        }, "Multiple EmptyIterator instances should behave consistently");
    }

    @Test
    @DisplayName("EmptyIterator should support try-with-resources")
    void testTryWithResources() {
        // When & Then
        assertDoesNotThrow(() -> {
            try (EmptyIterator iterator = new EmptyIterator()) {
                assertFalse(iterator.hasNext(), "Iterator should be empty in try-with-resources");
                assertNull(iterator.next(), "Iterator should return null in try-with-resources");
            } catch (CIFSException e) {
                throw new RuntimeException(e);
            }
        }, "EmptyIterator should work with try-with-resources");
    }

    @Test
    @DisplayName("EmptyIterator should work with manual iteration")
    void testManualIteration() {
        // When & Then
        assertDoesNotThrow(() -> {
            int count = 0;
            while (emptyIterator.hasNext()) {
                emptyIterator.next();
                count++;
                if (count > 10)
                    break; // Safety check
            }
            assertEquals(0, count, "No iterations should occur for empty iterator");
        }, "EmptyIterator should work with manual iteration");
    }

    @Test
    @DisplayName("EmptyIterator should handle concurrent access safely")
    void testConcurrentAccess() throws InterruptedException, CIFSException {
        // Given
        final int threadCount = 10;
        final Thread[] threads = new Thread[threadCount];
        final boolean[] results = new boolean[threadCount];

        try (EmptyIterator sharedIterator = new EmptyIterator()) {
            // When
            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                threads[i] = new Thread(() -> {
                    // Each thread performs multiple operations
                    for (int j = 0; j < 100; j++) {
                        boolean hasNext = sharedIterator.hasNext();
                        SmbResource next = sharedIterator.next();

                        if (hasNext || next != null) {
                            results[index] = false; // Mark as failed if unexpected result
                            return;
                        }
                    }
                    results[index] = true; // Mark as successful
                });
                threads[i].start();
            }

            // Wait for all threads to complete
            for (Thread thread : threads) {
                thread.join();
            }
        }

        // Then
        for (int i = 0; i < threadCount; i++) {
            assertTrue(results[i], "Thread " + i + " should have completed successfully");
        }
    }

    @Test
    @DisplayName("EmptyIterator should handle close operations multiple times")
    void testMultipleCloseOperations() {
        // When & Then
        assertDoesNotThrow(() -> {
            try {
                emptyIterator.close();
                emptyIterator.close();
                emptyIterator.close();
            } catch (CIFSException e) {
                throw new RuntimeException(e);
            }
        }, "Multiple close operations should not cause issues");

        // Verify iterator still works after multiple closes
        assertFalse(emptyIterator.hasNext(), "Iterator should still work after multiple closes");
        assertNull(emptyIterator.next(), "Iterator should still return null after multiple closes");
    }

    @Test
    @DisplayName("EmptyIterator should handle remove operations multiple times")
    void testMultipleRemoveOperations() {
        // When & Then
        assertDoesNotThrow(() -> {
            emptyIterator.remove();
            emptyIterator.remove();
            emptyIterator.remove();
        }, "Multiple remove operations should not cause issues");

        // Verify iterator still works after multiple removes
        assertFalse(emptyIterator.hasNext(), "Iterator should still work after multiple removes");
        assertNull(emptyIterator.next(), "Iterator should still return null after multiple removes");
    }

    @Test
    @DisplayName("EmptyIterator should maintain state after all operations")
    void testStateConsistencyAfterOperations() {
        // When - perform various operations
        assertFalse(emptyIterator.hasNext(), "Initial hasNext check");
        assertNull(emptyIterator.next(), "Initial next call");

        emptyIterator.remove();
        assertFalse(emptyIterator.hasNext(), "hasNext after remove");
        assertNull(emptyIterator.next(), "next after remove");

        assertDoesNotThrow(() -> {
            try {
                emptyIterator.close();
            } catch (CIFSException e) {
                throw new RuntimeException(e);
            }
        }, "close operation");
        assertFalse(emptyIterator.hasNext(), "hasNext after close");
        assertNull(emptyIterator.next(), "next after close");

        // Then - verify final state
        assertFalse(emptyIterator.hasNext(), "Final hasNext check");
        assertNull(emptyIterator.next(), "Final next call");
    }

    @Test
    @DisplayName("EmptyIterator should be lightweight and efficient")
    void testPerformanceCharacteristics() {
        // When - create many instances quickly
        long startTime = System.currentTimeMillis();

        for (int i = 0; i < 10000; i++) {
            EmptyIterator iterator = new EmptyIterator();
            iterator.hasNext();
            iterator.next();
            iterator.remove();
            assertDoesNotThrow(() -> {
                try {
                    iterator.close();
                } catch (CIFSException e) {
                    throw new RuntimeException(e);
                }
            });
        }

        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;

        // Then - should complete quickly (this is more of a performance indicator)
        assertTrue(duration < 1000, "Creating and using 10000 EmptyIterators should be fast (took " + duration + "ms)");
    }

    @Test
    @DisplayName("EmptyIterator should work correctly in nested iteration")
    void testNestedIteration() {
        // When & Then
        assertDoesNotThrow(() -> {
            int outerCount = 0;
            while (emptyIterator.hasNext()) {
                emptyIterator.next();
                outerCount++;

                int innerCount = 0;
                try (EmptyIterator innerIterator = new EmptyIterator()) {
                    while (innerIterator.hasNext()) {
                        innerIterator.next();
                        innerCount++;
                    }
                }
                assertEquals(0, innerCount, "Inner iteration should not execute");
            }
            assertEquals(0, outerCount, "Outer iteration should not execute");
        }, "EmptyIterator should work correctly in nested iteration");
    }

    @Test
    @DisplayName("EmptyIterator should follow Iterator contract for empty collections")
    void testIteratorContract() {
        // Given - typical Iterator usage pattern

        // When & Then - verify empty collection behavior
        assertFalse(emptyIterator.hasNext(), "Empty iterator should have no next element");

        // Note: Standard Iterator would throw NoSuchElementException, but this implementation returns null
        // This is a design choice for this specific implementation
        assertNull(emptyIterator.next(), "This implementation returns null instead of throwing");

        // Verify remove can be called (even though no-op)
        assertDoesNotThrow(() -> emptyIterator.remove(), "remove() should be safe to call");

        // Verify still empty after operations
        assertFalse(emptyIterator.hasNext(), "Should remain empty after operations");
    }
}