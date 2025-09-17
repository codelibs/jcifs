package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.stream.Stream;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.ResourceFilter;
import org.codelibs.jcifs.smb.SmbResource;
import org.codelibs.jcifs.smb.SmbResourceLocator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SmbEnumerationUtilTest {

    @Mock
    SmbFilenameFilter fnf;

    @Mock
    SmbFileFilter ff;

    // Utility to create a private inner class instance reflectively
    private static Object newPrivateInner(String simpleName, Class<?>[] paramTypes, Object... args) {
        try {
            Class<?> cls = Class.forName("org.codelibs.jcifs.smb.impl.SmbEnumerationUtil$" + simpleName);
            Constructor<?> ctor = cls.getDeclaredConstructor(paramTypes);
            ctor.setAccessible(true);
            return ctor.newInstance(args);
        } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException
                | InvocationTargetException e) {
            throw new AssertionError(e);
        }
    }

    // Utility to invoke a private method reflectively
    private static Object invokePrivate(Object targetOrClass, String methodName, Class<?>[] paramTypes, Object... args) {
        try {
            final Class<?> cls = targetOrClass instanceof Class<?> ? (Class<?>) targetOrClass : targetOrClass.getClass();
            Method m = cls.getDeclaredMethod(methodName, paramTypes);
            m.setAccessible(true);
            return m.invoke(targetOrClass instanceof Class<?> ? null : targetOrClass, args);
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            throw new AssertionError(e);
        }
    }

    @Nested
    @DisplayName("doShareEnum early validation")
    class DoShareEnumValidation {

        static Stream<Arguments> invalidShareEnumCases() {
            return Stream.of(
                    // Missing trailing slash -> should complain about directory ending
                    Arguments.of("smb://server/share", "/share", true),
                    // Not a server root -> invalid list operation
                    Arguments.of("smb://server/share/", "/share/", false));
        }

        @ParameterizedTest(name = "invalid path: {0}")
        @MethodSource("invalidShareEnumCases")
        void doShareEnum_invalidPath_throws(String url, String pathSuffix, boolean expectDirSlashMsg) throws Exception {
            // Arrange
            SmbFile parent = new SmbFile(url);

            // Act + Assert
            SmbException ex = assertThrows(SmbException.class, () -> SmbEnumerationUtil.doShareEnum(parent, "*", 0, null, null));

            // Assert message indicates which validation failed
            if (expectDirSlashMsg) {
                assertTrue(ex.getMessage().contains("directory must end with '/'"),
                        "Expected trailing slash message, was: " + ex.getMessage());
            } else {
                assertTrue(ex.getMessage().contains("invalid") || ex.getMessage().contains("invalid:"),
                        "Expected invalid list operation message, was: " + ex.getMessage());
            }
        }
    }

    @Nested
    @DisplayName("Master browser enumeration tests")
    class MasterBrowserEnumerationTests {

        @Test
        @DisplayName("doEnum with empty host throws SmbUnsupportedOperationException when master browser not found")
        void doEnum_withEmptyHost_throwsUnsupportedWithoutNetwork() throws Exception {
            // Arrange: mock parent + locator so no real network is used
            SmbFile parent = mock(SmbFile.class, RETURNS_DEEP_STUBS);
            SmbResourceLocator locator = mock(SmbResourceLocator.class);
            when(parent.getLocator()).thenReturn(locator);
            // Host is empty -> triggers master browser path
            URL anyUrlWithEmptyHost = new URL("file:/");
            when(locator.getURL()).thenReturn(anyUrlWithEmptyHost);
            // Simulate failure to find master browser (UnknownHost wrapped in CIFSException)
            when(locator.getAddress()).thenThrow(new CIFSException("no master", new UnknownHostException("MB")));

            // Act + Assert: the code maps this case to SmbUnsupportedOperationException
            assertThrows(SmbUnsupportedOperationException.class, () -> SmbEnumerationUtil.doEnum(parent, "*", 0, null, null));
        }

        @Test
        @DisplayName("list propagates SmbUnsupportedOperationException from doEnum")
        void list_propagatesUnsupportedOperationException() throws Exception {
            // Arrange: same setup as above to force doEnum -> SmbUnsupportedOperationException
            SmbFile parent = mock(SmbFile.class, RETURNS_DEEP_STUBS);
            SmbResourceLocator locator = mock(SmbResourceLocator.class);
            when(parent.getLocator()).thenReturn(locator);
            when(locator.getURL()).thenReturn(new URL("file:/"));
            when(locator.getAddress()).thenThrow(new CIFSException("no master", new UnknownHostException("MB")));

            // Act + Assert: doEnum throws SmbUnsupportedOperationException which is returned as-is
            SmbUnsupportedOperationException ex =
                    assertThrows(SmbUnsupportedOperationException.class, () -> SmbEnumerationUtil.list(parent, "*", 0, null, null));
            // SmbUnsupportedOperationException is directly thrown, not wrapped
            assertNotNull(ex);
        }

        @Test
        @DisplayName("listFiles propagates SmbUnsupportedOperationException from doEnum")
        void listFiles_propagatesUnsupportedOperationException() throws Exception {
            // Arrange: same setup to force doEnum failure
            SmbFile parent = mock(SmbFile.class, RETURNS_DEEP_STUBS);
            SmbResourceLocator locator = mock(SmbResourceLocator.class);
            when(parent.getLocator()).thenReturn(locator);
            when(locator.getURL()).thenReturn(new URL("file:/"));
            when(locator.getAddress()).thenThrow(new CIFSException("no master", new UnknownHostException("MB")));

            // Act + Assert: doEnum throws SmbUnsupportedOperationException which is returned as-is
            SmbUnsupportedOperationException ex =
                    assertThrows(SmbUnsupportedOperationException.class, () -> SmbEnumerationUtil.listFiles(parent, "*", 0, null, null));
            // SmbUnsupportedOperationException is directly thrown, not wrapped
            assertNotNull(ex);
        }
    }

    @Nested
    @DisplayName("Input validation tests")
    class InputValidationTests {

        @Test
        @DisplayName("list with null root throws NullPointerException")
        void list_withNullRoot_throwsNpe() {
            // Intent: null root is invalid input
            assertThrows(NullPointerException.class, () -> SmbEnumerationUtil.list(null, "*", 0, null, null));
        }

        @Test
        @DisplayName("listFiles with null root throws NullPointerException")
        void listFiles_withNullRoot_throwsNpe() {
            // Intent: null root is invalid input
            assertThrows(NullPointerException.class, () -> SmbEnumerationUtil.listFiles(null, "*", 0, null, null));
        }

        @Test
        @DisplayName("doEnum with null parent throws NullPointerException")
        void doEnum_withNullParent_throwsNpe() {
            assertThrows(NullPointerException.class, () -> SmbEnumerationUtil.doEnum(null, "*", 0, null, null));
        }
    }

    @Nested
    @DisplayName("Wrapper behaviors")
    class WrapperBehaviorTests {

        @Test
        void resourceFilterWrapper_accept_falseForNonSmbFile_andNoDelegation() throws Exception {
            // Arrange
            SmbFileFilter delegate = mock(SmbFileFilter.class);
            Object wrapper = newPrivateInner("ResourceFilterWrapper", new Class<?>[] { SmbFileFilter.class }, delegate);

            SmbResource notAFile = mock(SmbResource.class);

            // Act
            boolean result = (boolean) invokePrivate(wrapper, "accept", new Class<?>[] { SmbResource.class }, notAFile);

            // Assert
            assertFalse(result);
            verify(delegate, never()).accept(any());
        }

        @Test
        void resourceFilterWrapper_accept_trueDelegatesToFilter() throws Exception {
            // Arrange
            SmbFileFilter delegate = mock(SmbFileFilter.class);
            Object wrapper = newPrivateInner("ResourceFilterWrapper", new Class<?>[] { SmbFileFilter.class }, delegate);

            SmbFile smbFile = mock(SmbFile.class);
            when(delegate.accept(smbFile)).thenReturn(true);

            // Act
            boolean result = (boolean) invokePrivate(wrapper, "accept", new Class<?>[] { SmbResource.class }, smbFile);

            // Assert
            assertTrue(result);
            verify(delegate, times(1)).accept(smbFile);
        }

        @Test
        void resourceNameFilterWrapper_accept_falseForNonSmbFileParent_andNoDelegation() throws Exception {
            // Arrange
            SmbFilenameFilter delegate = mock(SmbFilenameFilter.class);
            Object wrapper = newPrivateInner("ResourceNameFilterWrapper", new Class<?>[] { SmbFilenameFilter.class }, delegate);

            SmbResource notAFileParent = mock(SmbResource.class);

            // Act
            boolean result =
                    (boolean) invokePrivate(wrapper, "accept", new Class<?>[] { SmbResource.class, String.class }, notAFileParent, "name");

            // Assert
            assertFalse(result);
            verify(delegate, never()).accept(any(), any());
        }

        @Test
        void resourceNameFilterWrapper_accept_delegatesToFilter() throws Exception {
            // Arrange
            SmbFilenameFilter delegate = mock(SmbFilenameFilter.class);
            Object wrapper = newPrivateInner("ResourceNameFilterWrapper", new Class<?>[] { SmbFilenameFilter.class }, delegate);

            SmbFile parent = mock(SmbFile.class);
            when(delegate.accept(parent, "x")).thenReturn(true);

            // Act
            boolean result = (boolean) invokePrivate(wrapper, "accept", new Class<?>[] { SmbResource.class, String.class }, parent, "x");

            // Assert
            assertTrue(result);
            verify(delegate, times(1)).accept(parent, "x");
        }

        @Test
        void resourceFilterWrapper_exposesWrappedFilter_viaGetFileFilter() throws Exception {
            // Arrange
            SmbFileFilter delegate = mock(SmbFileFilter.class);
            Object wrapper = newPrivateInner("ResourceFilterWrapper", new Class<?>[] { SmbFileFilter.class }, delegate);

            // Act
            Object returned = invokePrivate(wrapper, "getFileFilter", new Class<?>[] {});

            // Assert
            assertSame(delegate, returned);
        }

        @Test
        void unwrapDOSFilter_returnsInnerDosFileFilter_whenWrapped() throws Exception {
            // Arrange: create a ResourceFilterWrapper that wraps a DosFileFilter
            DosFileFilter dos = new DosFileFilter("abc", 7);
            Object wrapper = newPrivateInner("ResourceFilterWrapper", new Class<?>[] { SmbFileFilter.class }, dos);
            // unwrapDOSFilter is a private static method on SmbEnumerationUtil
            Class<?> utilClass = SmbEnumerationUtil.class;

            // Act
            Object unwrapped = invokePrivate(utilClass, "unwrapDOSFilter", new Class<?>[] { ResourceFilter.class }, wrapper);

            // Assert
            assertNotNull(unwrapped);
            assertTrue(unwrapped instanceof DosFileFilter);

            // Verify fields preserved (via reflection since they are protected)
            var wildcardField = DosFileFilter.class.getDeclaredField("wildcard");
            wildcardField.setAccessible(true);
            var attributesField = DosFileFilter.class.getDeclaredField("attributes");
            attributesField.setAccessible(true);

            assertEquals("abc", wildcardField.get(unwrapped));
            assertEquals(7, attributesField.get(unwrapped));
        }

        @Test
        void unwrapDOSFilter_returnsNull_whenNotWrapperOrNotDosFilter() {
            // Not a wrapper
            ResourceFilter rf = mock(ResourceFilter.class);
            Object unwrapped = invokePrivate(SmbEnumerationUtil.class, "unwrapDOSFilter", new Class<?>[] { ResourceFilter.class }, rf);
            assertNull(unwrapped);
        }

        @Test
        void unwrapDOSFilter_returnsNull_whenWrapperButNotDosFilter() throws Exception {
            // Wrapper but not wrapping a DosFileFilter
            SmbFileFilter nonDosFilter = mock(SmbFileFilter.class);
            Object wrapper = newPrivateInner("ResourceFilterWrapper", new Class<?>[] { SmbFileFilter.class }, nonDosFilter);

            Object unwrapped = invokePrivate(SmbEnumerationUtil.class, "unwrapDOSFilter", new Class<?>[] { ResourceFilter.class }, wrapper);
            assertNull(unwrapped);
        }
    }

    @Nested
    @DisplayName("Exception handling tests")
    class ExceptionHandlingTests {

        @Test
        @DisplayName("doEnum rethrows CIFSException when not UnknownHostException")
        void doEnum_rethrowsCIFSException_whenNotUnknownHost() throws Exception {
            // Arrange
            SmbFile parent = mock(SmbFile.class, RETURNS_DEEP_STUBS);
            SmbResourceLocator locator = mock(SmbResourceLocator.class);
            when(parent.getLocator()).thenReturn(locator);
            when(locator.getURL()).thenReturn(new URL("file:/"));
            // Throw CIFSException with different cause
            CIFSException differentException = new CIFSException("different error");
            when(locator.getAddress()).thenThrow(differentException);

            // Act + Assert
            CIFSException thrown = assertThrows(CIFSException.class, () -> SmbEnumerationUtil.doEnum(parent, "*", 0, null, null));
            assertSame(differentException, thrown);
        }

        @Test
        @DisplayName("list wraps non-SmbException CIFSException properly")
        void list_wrapsOtherCIFSException() throws Exception {
            // Arrange
            SmbFile parent = mock(SmbFile.class, RETURNS_DEEP_STUBS);
            SmbResourceLocator locator = mock(SmbResourceLocator.class);
            when(parent.getLocator()).thenReturn(locator);
            when(locator.getURL()).thenReturn(new URL("file:/"));
            CIFSException cifsEx = new CIFSException("test error");
            when(locator.getAddress()).thenThrow(cifsEx);

            // Act + Assert
            SmbException thrown = assertThrows(SmbException.class, () -> SmbEnumerationUtil.list(parent, "*", 0, null, null));
            assertSame(cifsEx, thrown.getCause());
        }
    }

    @Nested
    @DisplayName("DosFileFilter integration tests")
    class DosFileFilterTests {

        @Test
        @DisplayName("DosFileFilter wildcard and attributes are preserved through unwrap")
        void dosFileFilter_preservesFieldsThroughUnwrap() throws Exception {
            // Test with various wildcard patterns and attribute masks
            String[] wildcards = { "*.txt", "test*", null };
            int[] attributes = { 0x10, 0x20, 0x07 };

            for (int i = 0; i < wildcards.length; i++) {
                DosFileFilter dos = new DosFileFilter(wildcards[i], attributes[i]);
                Object wrapper = newPrivateInner("ResourceFilterWrapper", new Class<?>[] { SmbFileFilter.class }, dos);

                Object unwrapped =
                        invokePrivate(SmbEnumerationUtil.class, "unwrapDOSFilter", new Class<?>[] { ResourceFilter.class }, wrapper);
                assertNotNull(unwrapped);
                assertTrue(unwrapped instanceof DosFileFilter);

                var wildcardField = DosFileFilter.class.getDeclaredField("wildcard");
                wildcardField.setAccessible(true);
                var attributesField = DosFileFilter.class.getDeclaredField("attributes");
                attributesField.setAccessible(true);

                assertEquals(wildcards[i], wildcardField.get(unwrapped));
                assertEquals(attributes[i], attributesField.get(unwrapped));
            }
        }
    }
}
