package jcifs;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base test class providing common test infrastructure and utilities.
 * All test classes should extend this to ensure consistent test setup.
 */
@ExtendWith(MockitoExtension.class)
public abstract class BaseTest {

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    @BeforeEach
    void baseSetUp() {
        // Common setup for all tests
        logger.debug("Setting up test: {}", getClass().getSimpleName());
    }

    /**
     * Create a test byte array with specified size and pattern
     */
    protected byte[] createTestData(int size) {
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            data[i] = (byte) (i % 256);
        }
        return data;
    }

    /**
     * Create a test string with specified length
     */
    protected String createTestString(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append((char) ('A' + (i % 26)));
        }
        return sb.toString();
    }
}