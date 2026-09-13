package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.UUID;

import org.codelibs.jcifs.smb1.util.LogStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@link Config#getInt(String, int)}, the lookup a caller makes to find out whether a setting such as
 * {@code jcifs.util.loglevel} was configured before choosing its own value.
 */
class ConfigTest {

    private int savedLevel;

    @BeforeEach
    void quiet() {
        // An unparsable value prints its stack trace to the log above level 0.
        this.savedLevel = LogStream.level;
        LogStream.setLevel(0);
    }

    @AfterEach
    void restore() {
        LogStream.setLevel(this.savedLevel);
    }

    private static String uniqueKey() {
        return "jcifs.test.config." + UUID.randomUUID();
    }

    @Test
    @DisplayName("a key that was never set answers the caller's default")
    void unsetKeyAnswersTheDefault() {
        assertEquals(-1, Config.getInt(uniqueKey(), -1));
    }

    @Test
    @DisplayName("a key set to a number answers that number")
    void numericValueIsParsed() {
        final String key = uniqueKey();
        Config.setProperty(key, "3");

        assertEquals(3, Config.getInt(key, -1));
    }

    @Test
    @DisplayName("a key set to something that is not a number answers the default")
    void unparsableValueAnswersTheDefault() {
        final String key = uniqueKey();
        Config.setProperty(key, "verbose");

        assertEquals(-1, Config.getInt(key, -1));
    }
}
