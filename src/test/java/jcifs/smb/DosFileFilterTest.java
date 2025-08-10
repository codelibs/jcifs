/*
 * Copyright (c) 2024, CodeLibs. All rights reserved.
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
package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for the {@link DosFileFilter} class.
 */
@ExtendWith(MockitoExtension.class)
class DosFileFilterTest {

    @Mock
    private SmbFile mockFile;

    private DosFileFilter dosFileFilter;

    @BeforeEach
    void setUp() {
        // Basic setup, specific filter attributes will be set in each test
    }

    /**
     * Tests the constructor of DosFileFilter.
     * This test ensures that the constructor runs without errors and correctly initializes the object.
     * The wildcard parameter is stored but its filtering logic is handled server-side,
     * so we only verify its acceptance here.
     */
    @Test
    void testConstructor() {
        // The constructor should not throw any exceptions with valid inputs.
        new DosFileFilter("*.*", SmbFile.ATTR_ARCHIVE);
        new DosFileFilter("?", SmbFile.ATTR_DIRECTORY);
        new DosFileFilter("file.txt", SmbFile.ATTR_READONLY | SmbFile.ATTR_HIDDEN);
    }

    /**
     * Parameterized test for the {@link DosFileFilter#accept(SmbFile)} method.
     * This test covers various combinations of file attributes and filter attributes
     * to ensure the bitwise logic is correctly implemented.
     *
     * @param filterAttributes The attributes set for the filter.
     * @param fileAttributes The attributes of the mock file.
     * @param expectedResult The expected outcome of the accept method.
     * @throws SmbException If an SMB error occurs.
     */
    @ParameterizedTest(name = "Filter: {0}, File: {1}, Expected: {2}")
    @CsvSource({
        // Positive cases (should be accepted)
        "1, 1, true",   // ATTR_READONLY
        "2, 2, true",   // ATTR_HIDDEN
        "4, 4, true",   // ATTR_SYSTEM
        "16, 16, true", // ATTR_DIRECTORY
        "32, 32, true", // ATTR_ARCHIVE
        "3, 1, true",   // READONLY | HIDDEN vs READONLY
        "3, 2, true",   // READONLY | HIDDEN vs HIDDEN
        "3, 3, true",   // READONLY | HIDDEN vs READONLY | HIDDEN
        "48, 16, true", // DIRECTORY | ARCHIVE vs DIRECTORY
        "48, 32, true", // DIRECTORY | ARCHIVE vs ARCHIVE
        "21, 5, true",  // READONLY | SYSTEM | DIRECTORY vs READONLY | SYSTEM

        // Negative cases (should be rejected)
        "1, 2, false",  // READONLY vs HIDDEN
        "2, 1, false",  // HIDDEN vs READONLY
        "16, 32, false",// DIRECTORY vs ARCHIVE
        "3, 4, false",  // READONLY | HIDDEN vs SYSTEM
        "0, 1, false",  // No filter attributes
        "1, 0, false",  // No file attributes
        "0, 0, false"   // No attributes on either
    })
    void testAccept(int filterAttributes, int fileAttributes, boolean expectedResult) throws SmbException {
        // Given a DosFileFilter with specific attributes
        dosFileFilter = new DosFileFilter("*.*", filterAttributes);

        // and a mock SmbFile with specific attributes
        when(mockFile.getAttributes()).thenReturn(fileAttributes);

        // When the accept method is called
        boolean result = dosFileFilter.accept(mockFile);

        // Then the result should be as expected
        if (expectedResult) {
            assertTrue(result, "File should be accepted");
        } else {
            assertFalse(result, "File should not be accepted");
        }
    }

    /**
     * Tests that the accept method returns true when the file has more attributes
     * than the filter, but all filter attributes are present in the file's attributes.
     * @throws SmbException if an SMB error occurs.
     */
    @Test
    void testAccept_FileHasMoreAttributes_Matching() throws SmbException {
        // Given a filter for READONLY
        dosFileFilter = new DosFileFilter("*", SmbFile.ATTR_READONLY);
        // and a file that is READONLY, HIDDEN, and SYSTEM
        when(mockFile.getAttributes()).thenReturn(SmbFile.ATTR_READONLY | SmbFile.ATTR_HIDDEN | SmbFile.ATTR_SYSTEM);

        // When calling accept
        // Then it should be accepted because the READONLY attribute is present
        assertTrue(dosFileFilter.accept(mockFile));
    }

    /**
     * Tests that the accept method returns false when the file attributes do not
     * contain any of the attributes specified in the filter.
     * @throws SmbException if an SMB error occurs.
     */
    @Test
    void testAccept_FileHasMoreAttributes_NonMatching() throws SmbException {
        // Given a filter for ARCHIVE
        dosFileFilter = new DosFileFilter("*", SmbFile.ATTR_ARCHIVE);
        // and a file that is READONLY, HIDDEN, and SYSTEM
        when(mockFile.getAttributes()).thenReturn(SmbFile.ATTR_READONLY | SmbFile.ATTR_HIDDEN | SmbFile.ATTR_SYSTEM);

        // When calling accept
        // Then it should be rejected because the ARCHIVE attribute is not present
        assertFalse(dosFileFilter.accept(mockFile));
    }

    /**
     * Tests that the accept method correctly propagates SmbException when
     * {@link SmbFile#getAttributes()} throws it.
     * @throws SmbException if an SMB error occurs.
     */
    @Test
    void testAccept_ThrowsSmbException() throws SmbException {
        // Given a filter
        dosFileFilter = new DosFileFilter("*.*", SmbFile.ATTR_ARCHIVE);
        // and a mock file that throws an exception when getAttributes is called
        SmbException expectedException = new SmbException("Failed to get attributes");
        when(mockFile.getAttributes()).thenThrow(expectedException);

        // When calling accept
        // Then an SmbException should be thrown
        SmbException thrown = assertThrows(SmbException.class, () -> {
            dosFileFilter.accept(mockFile);
        });

        // and the exception should be the one we configured
        assertTrue(thrown == expectedException);
    }
}
