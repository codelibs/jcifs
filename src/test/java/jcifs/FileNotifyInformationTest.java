package jcifs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Test class for FileNotifyInformation interface
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class FileNotifyInformationTest {

    @Mock
    private FileNotifyInformation mockFileNotifyInfo;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Nested
    @DisplayName("Filter Flags Constants Tests")
    class FilterFlagsTests {

        @Test
        @DisplayName("Verify FILE_NOTIFY_CHANGE_FILE_NAME constant value")
        void testFileNotifyChangeFileName() {
            assertEquals(0x00000001, FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME);
        }

        @Test
        @DisplayName("Verify FILE_NOTIFY_CHANGE_DIR_NAME constant value")
        void testFileNotifyChangeDirName() {
            assertEquals(0x00000002, FileNotifyInformation.FILE_NOTIFY_CHANGE_DIR_NAME);
        }

        @Test
        @DisplayName("Verify FILE_NOTIFY_CHANGE_NAME constant value")
        void testFileNotifyChangeName() {
            assertEquals(0x00000003, FileNotifyInformation.FILE_NOTIFY_CHANGE_NAME);
            // Verify it's a combination of FILE_NAME and DIR_NAME
            assertEquals(FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME | FileNotifyInformation.FILE_NOTIFY_CHANGE_DIR_NAME,
                    FileNotifyInformation.FILE_NOTIFY_CHANGE_NAME);
        }

        @Test
        @DisplayName("Verify FILE_NOTIFY_CHANGE_ATTRIBUTES constant value")
        void testFileNotifyChangeAttributes() {
            assertEquals(0x00000004, FileNotifyInformation.FILE_NOTIFY_CHANGE_ATTRIBUTES);
        }

        @Test
        @DisplayName("Verify FILE_NOTIFY_CHANGE_SIZE constant value")
        void testFileNotifyChangeSize() {
            assertEquals(0x00000008, FileNotifyInformation.FILE_NOTIFY_CHANGE_SIZE);
        }

        @Test
        @DisplayName("Verify FILE_NOTIFY_CHANGE_LAST_WRITE constant value")
        void testFileNotifyChangeLastWrite() {
            assertEquals(0x00000010, FileNotifyInformation.FILE_NOTIFY_CHANGE_LAST_WRITE);
        }

        @Test
        @DisplayName("Verify FILE_NOTIFY_CHANGE_LAST_ACCESS constant value")
        void testFileNotifyChangeLastAccess() {
            assertEquals(0x00000020, FileNotifyInformation.FILE_NOTIFY_CHANGE_LAST_ACCESS);
        }

        @Test
        @DisplayName("Verify FILE_NOTIFY_CHANGE_CREATION constant value")
        void testFileNotifyChangeCreation() {
            assertEquals(0x00000040, FileNotifyInformation.FILE_NOTIFY_CHANGE_CREATION);
        }

        @Test
        @DisplayName("Verify FILE_NOTIFY_CHANGE_EA constant value")
        void testFileNotifyChangeEa() {
            assertEquals(0x00000080, FileNotifyInformation.FILE_NOTIFY_CHANGE_EA);
        }

        @Test
        @DisplayName("Verify FILE_NOTIFY_CHANGE_SECURITY constant value")
        void testFileNotifyChangeSecurity() {
            assertEquals(0x00000100, FileNotifyInformation.FILE_NOTIFY_CHANGE_SECURITY);
        }

        @Test
        @DisplayName("Verify FILE_NOTIFY_CHANGE_STREAM_NAME constant value")
        void testFileNotifyChangeStreamName() {
            assertEquals(0x00000200, FileNotifyInformation.FILE_NOTIFY_CHANGE_STREAM_NAME);
        }

        @Test
        @DisplayName("Verify FILE_NOTIFY_CHANGE_STREAM_SIZE constant value")
        void testFileNotifyChangeStreamSize() {
            assertEquals(0x00000400, FileNotifyInformation.FILE_NOTIFY_CHANGE_STREAM_SIZE);
        }

        @Test
        @DisplayName("Verify FILE_NOTIFY_CHANGE_STREAM_WRITE constant value")
        void testFileNotifyChangeStreamWrite() {
            assertEquals(0x00000800, FileNotifyInformation.FILE_NOTIFY_CHANGE_STREAM_WRITE);
        }

        @Test
        @DisplayName("Verify filter flags are power of 2 for bitwise operations")
        void testFilterFlagsArePowerOfTwo() {
            // Verify each flag is a power of 2 (except FILE_NOTIFY_CHANGE_NAME which is a combination)
            assertTrue(isPowerOfTwo(FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME));
            assertTrue(isPowerOfTwo(FileNotifyInformation.FILE_NOTIFY_CHANGE_DIR_NAME));
            assertTrue(isPowerOfTwo(FileNotifyInformation.FILE_NOTIFY_CHANGE_ATTRIBUTES));
            assertTrue(isPowerOfTwo(FileNotifyInformation.FILE_NOTIFY_CHANGE_SIZE));
            assertTrue(isPowerOfTwo(FileNotifyInformation.FILE_NOTIFY_CHANGE_LAST_WRITE));
            assertTrue(isPowerOfTwo(FileNotifyInformation.FILE_NOTIFY_CHANGE_LAST_ACCESS));
            assertTrue(isPowerOfTwo(FileNotifyInformation.FILE_NOTIFY_CHANGE_CREATION));
            assertTrue(isPowerOfTwo(FileNotifyInformation.FILE_NOTIFY_CHANGE_EA));
            assertTrue(isPowerOfTwo(FileNotifyInformation.FILE_NOTIFY_CHANGE_SECURITY));
            assertTrue(isPowerOfTwo(FileNotifyInformation.FILE_NOTIFY_CHANGE_STREAM_NAME));
            assertTrue(isPowerOfTwo(FileNotifyInformation.FILE_NOTIFY_CHANGE_STREAM_SIZE));
            assertTrue(isPowerOfTwo(FileNotifyInformation.FILE_NOTIFY_CHANGE_STREAM_WRITE));
        }

        @Test
        @DisplayName("Verify no filter flag overlap except for combined flags")
        void testNoFilterFlagOverlap() {
            int[] flags = { FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME, FileNotifyInformation.FILE_NOTIFY_CHANGE_DIR_NAME,
                    FileNotifyInformation.FILE_NOTIFY_CHANGE_ATTRIBUTES, FileNotifyInformation.FILE_NOTIFY_CHANGE_SIZE,
                    FileNotifyInformation.FILE_NOTIFY_CHANGE_LAST_WRITE, FileNotifyInformation.FILE_NOTIFY_CHANGE_LAST_ACCESS,
                    FileNotifyInformation.FILE_NOTIFY_CHANGE_CREATION, FileNotifyInformation.FILE_NOTIFY_CHANGE_EA,
                    FileNotifyInformation.FILE_NOTIFY_CHANGE_SECURITY, FileNotifyInformation.FILE_NOTIFY_CHANGE_STREAM_NAME,
                    FileNotifyInformation.FILE_NOTIFY_CHANGE_STREAM_SIZE, FileNotifyInformation.FILE_NOTIFY_CHANGE_STREAM_WRITE };

            // Check that no two flags overlap (except combined flags)
            for (int i = 0; i < flags.length; i++) {
                for (int j = i + 1; j < flags.length; j++) {
                    assertEquals(0, flags[i] & flags[j], String.format("Flags at index %d and %d should not overlap", i, j));
                }
            }
        }
    }

    @Nested
    @DisplayName("Action Constants Tests")
    class ActionConstantsTests {

        @Test
        @DisplayName("Verify FILE_ACTION_ADDED constant value")
        void testFileActionAdded() {
            assertEquals(0x00000001, FileNotifyInformation.FILE_ACTION_ADDED);
        }

        @Test
        @DisplayName("Verify FILE_ACTION_REMOVED constant value")
        void testFileActionRemoved() {
            assertEquals(0x00000002, FileNotifyInformation.FILE_ACTION_REMOVED);
        }

        @Test
        @DisplayName("Verify FILE_ACTION_MODIFIED constant value")
        void testFileActionModified() {
            assertEquals(0x00000003, FileNotifyInformation.FILE_ACTION_MODIFIED);
        }

        @Test
        @DisplayName("Verify FILE_ACTION_RENAMED_OLD_NAME constant value")
        void testFileActionRenamedOldName() {
            assertEquals(0x00000004, FileNotifyInformation.FILE_ACTION_RENAMED_OLD_NAME);
        }

        @Test
        @DisplayName("Verify FILE_ACTION_RENAMED_NEW_NAME constant value")
        void testFileActionRenamedNewName() {
            assertEquals(0x00000005, FileNotifyInformation.FILE_ACTION_RENAMED_NEW_NAME);
        }

        @Test
        @DisplayName("Verify FILE_ACTION_ADDED_STREAM constant value")
        void testFileActionAddedStream() {
            assertEquals(0x00000006, FileNotifyInformation.FILE_ACTION_ADDED_STREAM);
        }

        @Test
        @DisplayName("Verify FILE_ACTION_REMOVED_STREAM constant value")
        void testFileActionRemovedStream() {
            assertEquals(0x00000007, FileNotifyInformation.FILE_ACTION_REMOVED_STREAM);
        }

        @Test
        @DisplayName("Verify FILE_ACTION_MODIFIED_STREAM constant value")
        void testFileActionModifiedStream() {
            assertEquals(0x00000008, FileNotifyInformation.FILE_ACTION_MODIFIED_STREAM);
        }

        @Test
        @DisplayName("Verify FILE_ACTION_REMOVED_BY_DELETE constant value")
        void testFileActionRemovedByDelete() {
            assertEquals(0x00000009, FileNotifyInformation.FILE_ACTION_REMOVED_BY_DELETE);
        }

        @Test
        @DisplayName("Verify action constants are sequential and unique")
        void testActionConstantsAreUnique() {
            int[] actions = { FileNotifyInformation.FILE_ACTION_ADDED, FileNotifyInformation.FILE_ACTION_REMOVED,
                    FileNotifyInformation.FILE_ACTION_MODIFIED, FileNotifyInformation.FILE_ACTION_RENAMED_OLD_NAME,
                    FileNotifyInformation.FILE_ACTION_RENAMED_NEW_NAME, FileNotifyInformation.FILE_ACTION_ADDED_STREAM,
                    FileNotifyInformation.FILE_ACTION_REMOVED_STREAM, FileNotifyInformation.FILE_ACTION_MODIFIED_STREAM,
                    FileNotifyInformation.FILE_ACTION_REMOVED_BY_DELETE };

            // Verify sequential values from 1 to 9
            for (int i = 0; i < actions.length; i++) {
                assertEquals(i + 1, actions[i], String.format("Action at index %d should have value %d", i, i + 1));
            }
        }
    }

    @Nested
    @DisplayName("Interface Methods Tests")
    class InterfaceMethodsTests {

        @Test
        @DisplayName("Test getAction method with mock")
        void testGetAction() {
            // Setup mock behavior
            when(mockFileNotifyInfo.getAction()).thenReturn(FileNotifyInformation.FILE_ACTION_ADDED);

            // Test
            int action = mockFileNotifyInfo.getAction();

            // Verify
            assertEquals(FileNotifyInformation.FILE_ACTION_ADDED, action);
            verify(mockFileNotifyInfo, times(1)).getAction();
        }

        @Test
        @DisplayName("Test getFileName method with mock")
        void testGetFileName() {
            // Setup mock behavior
            String expectedFileName = "test-file.txt";
            when(mockFileNotifyInfo.getFileName()).thenReturn(expectedFileName);

            // Test
            String fileName = mockFileNotifyInfo.getFileName();

            // Verify
            assertEquals(expectedFileName, fileName);
            verify(mockFileNotifyInfo, times(1)).getFileName();
        }

        @ParameterizedTest
        @ValueSource(ints = { 0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005, 0x00000006, 0x00000007, 0x00000008, 0x00000009 })
        @DisplayName("Test getAction with various action values")
        void testGetActionWithVariousValues(int actionValue) {
            when(mockFileNotifyInfo.getAction()).thenReturn(actionValue);
            assertEquals(actionValue, mockFileNotifyInfo.getAction());
        }

        @ParameterizedTest
        @CsvSource({ "file.txt", "document.doc", "image.png", "folder/subfolder/file.txt", "C:\\Windows\\System32\\config.sys",
                "/usr/local/bin/app", "file with spaces.txt", "''" // empty string
        })
        @DisplayName("Test getFileName with various file names")
        void testGetFileNameWithVariousValues(String fileName) {
            when(mockFileNotifyInfo.getFileName()).thenReturn(fileName);
            assertEquals(fileName, mockFileNotifyInfo.getFileName());
        }

        @Test
        @DisplayName("Test getFileName with null value")
        void testGetFileNameWithNull() {
            when(mockFileNotifyInfo.getFileName()).thenReturn(null);
            assertNull(mockFileNotifyInfo.getFileName());
        }
    }

    @Nested
    @DisplayName("Implementation Tests")
    class ImplementationTests {

        @Test
        @DisplayName("Test concrete implementation of FileNotifyInformation")
        void testConcreteImplementation() {
            // Create a simple implementation for testing
            FileNotifyInformation impl = new FileNotifyInformation() {
                private final int action = FileNotifyInformation.FILE_ACTION_MODIFIED;
                private final String fileName = "implementation-test.txt";

                @Override
                public int getAction() {
                    return action;
                }

                @Override
                public String getFileName() {
                    return fileName;
                }
            };

            // Test the implementation
            assertEquals(FileNotifyInformation.FILE_ACTION_MODIFIED, impl.getAction());
            assertEquals("implementation-test.txt", impl.getFileName());
        }

        @Test
        @DisplayName("Test multiple implementations with different values")
        void testMultipleImplementations() {
            // Create multiple implementations
            FileNotifyInformation addedImpl = createImplementation(FileNotifyInformation.FILE_ACTION_ADDED, "added.txt");
            FileNotifyInformation removedImpl = createImplementation(FileNotifyInformation.FILE_ACTION_REMOVED, "removed.txt");
            FileNotifyInformation modifiedImpl = createImplementation(FileNotifyInformation.FILE_ACTION_MODIFIED, "modified.txt");

            // Verify each implementation
            assertEquals(FileNotifyInformation.FILE_ACTION_ADDED, addedImpl.getAction());
            assertEquals("added.txt", addedImpl.getFileName());

            assertEquals(FileNotifyInformation.FILE_ACTION_REMOVED, removedImpl.getAction());
            assertEquals("removed.txt", removedImpl.getFileName());

            assertEquals(FileNotifyInformation.FILE_ACTION_MODIFIED, modifiedImpl.getAction());
            assertEquals("modified.txt", modifiedImpl.getFileName());
        }
    }

    @Nested
    @DisplayName("Bit Manipulation Tests")
    class BitManipulationTests {

        @Test
        @DisplayName("Test combining multiple filter flags")
        void testCombiningFilterFlags() {
            int combinedFlags = FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME | FileNotifyInformation.FILE_NOTIFY_CHANGE_SIZE
                    | FileNotifyInformation.FILE_NOTIFY_CHANGE_LAST_WRITE;

            // Verify individual flags are set
            assertTrue((combinedFlags & FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME) != 0);
            assertTrue((combinedFlags & FileNotifyInformation.FILE_NOTIFY_CHANGE_SIZE) != 0);
            assertTrue((combinedFlags & FileNotifyInformation.FILE_NOTIFY_CHANGE_LAST_WRITE) != 0);

            // Verify other flags are not set
            assertFalse((combinedFlags & FileNotifyInformation.FILE_NOTIFY_CHANGE_ATTRIBUTES) != 0);
            assertFalse((combinedFlags & FileNotifyInformation.FILE_NOTIFY_CHANGE_SECURITY) != 0);
        }

        @Test
        @DisplayName("Test all filter flags combined")
        void testAllFilterFlagsCombined() {
            int allFlags = FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME | FileNotifyInformation.FILE_NOTIFY_CHANGE_DIR_NAME
                    | FileNotifyInformation.FILE_NOTIFY_CHANGE_ATTRIBUTES | FileNotifyInformation.FILE_NOTIFY_CHANGE_SIZE
                    | FileNotifyInformation.FILE_NOTIFY_CHANGE_LAST_WRITE | FileNotifyInformation.FILE_NOTIFY_CHANGE_LAST_ACCESS
                    | FileNotifyInformation.FILE_NOTIFY_CHANGE_CREATION | FileNotifyInformation.FILE_NOTIFY_CHANGE_EA
                    | FileNotifyInformation.FILE_NOTIFY_CHANGE_SECURITY | FileNotifyInformation.FILE_NOTIFY_CHANGE_STREAM_NAME
                    | FileNotifyInformation.FILE_NOTIFY_CHANGE_STREAM_SIZE | FileNotifyInformation.FILE_NOTIFY_CHANGE_STREAM_WRITE;

            // Expected value when all flags are combined
            assertEquals(0x00000FFF, allFlags);
        }

        @Test
        @DisplayName("Test removing specific filter flag")
        void testRemovingFilterFlag() {
            int flags = FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME | FileNotifyInformation.FILE_NOTIFY_CHANGE_SIZE
                    | FileNotifyInformation.FILE_NOTIFY_CHANGE_LAST_WRITE;

            // Remove FILE_NOTIFY_CHANGE_SIZE flag
            flags &= ~FileNotifyInformation.FILE_NOTIFY_CHANGE_SIZE;

            // Verify FILE_NOTIFY_CHANGE_SIZE is removed
            assertFalse((flags & FileNotifyInformation.FILE_NOTIFY_CHANGE_SIZE) != 0);

            // Verify other flags are still present
            assertTrue((flags & FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME) != 0);
            assertTrue((flags & FileNotifyInformation.FILE_NOTIFY_CHANGE_LAST_WRITE) != 0);
        }

        @Test
        @DisplayName("Test toggling filter flag")
        void testTogglingFilterFlag() {
            int flags = FileNotifyInformation.FILE_NOTIFY_CHANGE_FILE_NAME;

            // Toggle FILE_NOTIFY_CHANGE_SIZE flag (add it)
            flags ^= FileNotifyInformation.FILE_NOTIFY_CHANGE_SIZE;
            assertTrue((flags & FileNotifyInformation.FILE_NOTIFY_CHANGE_SIZE) != 0);

            // Toggle FILE_NOTIFY_CHANGE_SIZE flag again (remove it)
            flags ^= FileNotifyInformation.FILE_NOTIFY_CHANGE_SIZE;
            assertFalse((flags & FileNotifyInformation.FILE_NOTIFY_CHANGE_SIZE) != 0);
        }
    }

    // Helper methods
    private boolean isPowerOfTwo(int n) {
        return n > 0 && (n & (n - 1)) == 0;
    }

    private FileNotifyInformation createImplementation(final int action, final String fileName) {
        return new FileNotifyInformation() {
            @Override
            public int getAction() {
                return action;
            }

            @Override
            public String getFileName() {
                return fileName;
            }
        };
    }
}
