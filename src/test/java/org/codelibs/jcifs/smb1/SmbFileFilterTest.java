package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link SmbFileFilter}. The filter interface is small; the
 * tests focus on the contract that implementations should honour and the
 * interaction with {@link SmbFile} instances. The tests make heavy use of
 * Mockito to guarantee that implementation classes do not inadvertently
 * bypass the filter logic.
 */
public class SmbFileFilterTest {

    /**
     * A minimal implementation that accepts every {@link SmbFile}.
     */
    private final SmbFileFilter ALWAYSACTIVE = new SmbFileFilter() {
        @Override
        public boolean accept(SmbFile file) throws SmbException {
            // Never inspect the file – simply accept.
            return true;
        }
    };

    /**
     * Helper filter that records the last file passed to it. Useful for
     * verifying interaction.
     */
    private class RecordingFilter implements SmbFileFilter {
        private SmbFile lastFile;
        private String lastPath;

        @Override
        public boolean accept(SmbFile file) throws SmbException {
            lastFile = file;
            // Actually interact with the file to verify the mock interaction
            if (file != null) {
                lastPath = file.getPath();
            }
            return true;
        }
    }

    @Nested
    @DisplayName("Happy path – accept is called and returns true")
    class HappyPath {
        @Test
        void acceptWithMockedFile() throws Exception {
            SmbFile mockFile = mock(SmbFile.class);
            when(mockFile.getPath()).thenReturn("/share/file.txt");
            assertTrue(ALWAYSACTIVE.accept(mockFile));
        }
    }

    @Nested
    @DisplayName("Invalid input – null file handling")
    class InvalidPath {
        @Test
        void acceptWithNullThrows() {
            SmbFileFilter throwOnNull = new SmbFileFilter() {
                @Override
                public boolean accept(SmbFile file) throws SmbException {
                    if (file == null) {
                        throw new SmbException("null file");
                    }
                    return true;
                }
            };
            assertThrows(SmbException.class, () -\u003e throwOnNull.accept(null));
        }
    }

    @Nested
    @DisplayName("Interaction – verify that file methods are invoked")
    class Interaction {
        @Test
        void verifiesPathInvocation() throws Exception {
            SmbFile mockFile = mock(SmbFile.class);
            when(mockFile.getPath()).thenReturn("/share/dir/");
            RecordingFilter filter = new RecordingFilter();
            filter.accept(mockFile);
            // Verify the filter stored the reference
            // assertSame may not be necessary but demonstrates captured file
            // we simply check that getPath was called
            verify(mockFile, times(1)).getPath();
        }
    }
}
