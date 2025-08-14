package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * Tests for {@link SmbFilenameFilter}. Since the interface only defines
 * a single method, the tests simply ensure that the lambda expression
 * correctly implements the method and that any exception is propagated.
 */
class SmbFilenameFilterTest {

    @Test
    void acceptReturnsTrueWhenNameMatches() throws Exception {
        SmbFile dir = Mockito.mock(SmbFile.class);
        SmbFilenameFilter filter = (d, n) -> n.equalsIgnoreCase("hello.txt");
        assertTrue(filter.accept(dir, "Hello.TXT"));
    }

    @Test
    void acceptReturnsFalseWhenNameDoesNotMatch() throws Exception {
        SmbFile dir = Mockito.mock(SmbFile.class);
        SmbFilenameFilter filter = (d, n) -> n.equalsIgnoreCase("hello.txt");
        assertFalse(filter.accept(dir, "world.txt"));
    }

    @Test
    void acceptHandlesNullName() throws Exception {
        SmbFile dir = Mockito.mock(SmbFile.class);
        SmbFilenameFilter filter = (d, n) -> n != null && n.startsWith("a");
        assertFalse(filter.accept(dir, null));
    }

    @Test
    void acceptPropagatesException() {
        SmbFile dir = Mockito.mock(SmbFile.class);
        SmbFilenameFilter filter = (d, n) -> {
            throw new SmbException("forced exception");
        };
        Exception e = assertThrows(Exception.class, () -> filter.accept(dir, "any"));
        assertTrue(e instanceof SmbException);
    }
}
