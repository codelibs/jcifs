package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class DosFileFilterTest {

    private DosFileFilter filter;

    @BeforeEach
    public void setup() {
        filter = new DosFileFilter("*", SmbFile.ATTR_NORMAL);
    }

    @Test
    @DisplayName("accept should return true when file attributes match filter")
    public void acceptShouldReturnTrueWhenAttributesMatch() throws Exception {
        SmbFile file = mock(SmbFile.class);
        when(file.getAttributes()).thenReturn(SmbFile.ATTR_NORMAL);
        assertTrue(filter.accept(file), "Attributes match should be accepted");
        verify(file, times(1)).getAttributes();
    }

    @Test
    @DisplayName("accept should return false when file attributes do not match filter")
    public void acceptShouldReturnFalseWhenAttributesDoNotMatch() throws Exception {
        SmbFile file = mock(SmbFile.class);
        when(file.getAttributes()).thenReturn(SmbFile.ATTR_HIDDEN);
        assertFalse(filter.accept(file), "Attributes not matching should be rejected");
        verify(file, times(1)).getAttributes();
    }

    @Test
    @DisplayName("accept should ignore wildcard in filter pattern")
    public void acceptShouldIgnoreWildcard() throws Exception {
        // Wildcard shouldn't affect accept logic.
        DosFileFilter customFilter = new DosFileFilter("*.txt", SmbFile.ATTR_DIRECTORY);
        SmbFile file = mock(SmbFile.class);
        when(file.getAttributes()).thenReturn(SmbFile.ATTR_DIRECTORY);
        assertTrue(customFilter.accept(file), "Wildcard should be ignored in accept");
    }

    @Test
    @DisplayName("accept should throw NullPointerException when file is null")
    public void acceptShouldHandleNullFile() {
        assertThrows(NullPointerException.class, () -> filter.accept(null));
    }
}
