package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.util.Arrays;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class SmbResourceLocatorInternalTest {

    @Mock
    SmbResourceLocatorInternal locator;

    @Mock
    SmbResourceLocator other;

    @Mock
    DfsReferralData referral;

    // Reflection-based API checks ensure the interface contract is as expected
    @Test
    @DisplayName("Type hierarchy and method signatures are correct")
    void typeAndSignatures() throws Exception {
        Class<?> clazz = SmbResourceLocatorInternal.class;

        // Assert it's an interface and extends the right superinterface
        assertTrue(clazz.isInterface(), "Should be an interface");
        assertTrue(Arrays.asList(clazz.getInterfaces()).contains(SmbResourceLocator.class), "Should extend SmbResourceLocator");

        // shouldForceSigning(): boolean, no params, no checked exceptions
        Method m1 = clazz.getMethod("shouldForceSigning");
        assertEquals(boolean.class, m1.getReturnType());
        assertEquals(0, m1.getParameterCount());
        assertEquals(0, m1.getExceptionTypes().length);

        // overlaps(SmbResourceLocator): boolean, declares CIFSException
        Method m2 = clazz.getMethod("overlaps", SmbResourceLocator.class);
        assertEquals(boolean.class, m2.getReturnType());
        assertEquals(1, m2.getParameterCount());
        Class<?>[] ex = m2.getExceptionTypes();
        assertEquals(1, ex.length);
        assertEquals(CIFSException.class, ex[0]);

        // handleDFSReferral(DfsReferralData, String): String, no checked exceptions
        Method m3 = clazz.getMethod("handleDFSReferral", DfsReferralData.class, String.class);
        assertEquals(String.class, m3.getReturnType());
        assertEquals(2, m3.getParameterCount());
        assertEquals(0, m3.getExceptionTypes().length);

        // Package check to ensure we are validating the correct type
        assertEquals("org.codelibs.jcifs.smb", clazz.getPackage().getName());
    }

    // Happy path: shouldForceSigning returns the configured value
    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    @DisplayName("shouldForceSigning returns stubbed boolean value")
    void shouldForceSigningReturns(boolean expected) {
        when(locator.shouldForceSigning()).thenReturn(expected);

        boolean result = locator.shouldForceSigning();

        assertEquals(expected, result);
        verify(locator, times(1)).shouldForceSigning();
        verifyNoMoreInteractions(locator);
    }

    // Happy path: overlaps delegates to implementation and returns as stubbed
    @Test
    @DisplayName("overlaps returns true then false as stubbed")
    void overlapsReturnsTrueThenFalse() throws Exception {
        when(locator.overlaps(other)).thenReturn(true, false);

        assertTrue(locator.overlaps(other));
        assertFalse(locator.overlaps(other));

        verify(locator, times(2)).overlaps(other);
        verifyNoMoreInteractions(locator);
    }

    // Error path: overlaps may throw a CIFSException per signature
    @Test
    @DisplayName("overlaps throws CIFSException when implementation fails")
    void overlapsThrowsCifsException() throws Exception {
        when(locator.overlaps(any())).thenThrow(new CIFSException("Simulated failure"));

        CIFSException ex = assertThrows(CIFSException.class, () -> locator.overlaps(other));
        assertTrue(ex.getMessage().contains("Simulated failure"));

        verify(locator).overlaps(other);
        verifyNoMoreInteractions(locator);
    }

    // Happy path: handleDFSReferral returns a resolved path
    @Test
    @DisplayName("handleDFSReferral returns resolved UNC path as stubbed")
    void handleDfsReferralValidInputs() {
        // Edge-like Windows UNC-style: a single backslash in the path
        String reqPath = "\\";
        String resolved = "smb://server/share/path";
        when(locator.handleDFSReferral(referral, reqPath)).thenReturn(resolved);

        String out = locator.handleDFSReferral(referral, reqPath);
        assertEquals(resolved, out);

        // Verify exact argument interaction
        verify(locator, times(1)).handleDFSReferral(referral, reqPath);
        verifyNoMoreInteractions(locator);
    }

    // Edge / invalid: null referral or empty/blank path
    @Test
    @DisplayName("handleDFSReferral handles null referral and empty path")
    void handleDfsReferralNullAndEmpty() {
        when(locator.handleDFSReferral(null, "")).thenReturn("smb://server/share/");
        assertEquals("smb://server/share/", locator.handleDFSReferral(null, ""));
        verify(locator).handleDFSReferral(null, "");
        verifyNoMoreInteractions(locator);
    }

    // Invalid input: null reqPath leads to NPE from implementation
    @Test
    @DisplayName("handleDFSReferral throws NPE on null reqPath")
    void handleDfsReferralNullPathThrows() {
        when(locator.handleDFSReferral(any(), isNull())).thenThrow(new NullPointerException("reqPath"));
        NullPointerException npe = assertThrows(NullPointerException.class, () -> locator.handleDFSReferral(referral, null));
        assertTrue(npe.getMessage() == null || npe.getMessage().contains("reqPath"));
        verify(locator).handleDFSReferral(referral, null);
        verifyNoMoreInteractions(locator);
    }

    // Interaction detail: capture arguments passed to handleDFSReferral
    @Test
    @DisplayName("handleDFSReferral receives the exact arguments via captor")
    void handleDfsReferralArgumentCapture() {
        when(locator.handleDFSReferral(any(), any())).thenReturn("ok");
        String req = "some/path";
        locator.handleDFSReferral(referral, req);

        ArgumentCaptor<DfsReferralData> drCap = ArgumentCaptor.forClass(DfsReferralData.class);
        ArgumentCaptor<String> pathCap = ArgumentCaptor.forClass(String.class);
        verify(locator).handleDFSReferral(drCap.capture(), pathCap.capture());

        assertSame(referral, drCap.getValue());
        assertEquals(req, pathCap.getValue());
        verifyNoMoreInteractions(locator);
    }
}
