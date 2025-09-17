package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.SmbTransport;
import org.codelibs.jcifs.smb.SmbTree;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for SmbSessionInternal interface using Mockito to exercise
 * method contracts, checked exceptions, and interactions with collaborators.
 */
@ExtendWith(MockitoExtension.class)
public class SmbSessionInternalTest {

    @Mock
    private SmbSessionInternal session;

    @Mock
    private SmbTransport transport;

    @Mock
    private SmbTree tree;

    @BeforeEach
    void resetMocks() {
        Mockito.reset(session, transport, tree);
    }

    // Happy path: isInUse returns the mocked state
    @ParameterizedTest
    @DisplayName("isInUse reflects current mocked state")
    @ValueSource(booleans = { true, false })
    void isInUse_variants(boolean inUse) {
        when(session.isInUse()).thenReturn(inUse);

        boolean result = session.isInUse();

        assertEquals(inUse, result);
        verify(session, times(1)).isInUse();
    }

    // Happy path + edge: getSessionKey returns bytes, empty and null
    @Test
    @DisplayName("getSessionKey returns bytes, empty, then null")
    void getSessionKey_variants() throws CIFSException {
        byte[] key = new byte[] { 10, 20 };
        when(session.getSessionKey()).thenReturn(key, new byte[0], null);

        assertArrayEquals(key, session.getSessionKey());
        assertArrayEquals(new byte[0], session.getSessionKey());
        assertNull(session.getSessionKey());
        verify(session, times(3)).getSessionKey();
    }

    // Error propagation: getSessionKey throws CIFSException
    @Test
    @DisplayName("getSessionKey throws CIFSException on failure")
    void getSessionKey_throws() throws CIFSException {
        doThrow(new CIFSException("session key failure")).when(session).getSessionKey();

        CIFSException ex = assertThrows(CIFSException.class, () -> session.getSessionKey());
        assertTrue(ex.getMessage().contains("failure"));
        verify(session).getSessionKey();
    }

    // Happy path: transport is returned and verified
    @Test
    @DisplayName("getTransport returns mocked transport")
    void getTransport_happy() {
        when(session.getTransport()).thenReturn(transport);
        assertSame(transport, session.getTransport());
        verify(session).getTransport();
    }

    // Happy path: connect to logon share completes without exception
    @Test
    @DisplayName("treeConnectLogon performs call without exception")
    void treeConnectLogon_happy() throws SmbException {
        // doNothing by default
        session.treeConnectLogon();
        verify(session, times(1)).treeConnectLogon();
    }

    // Error propagation: connect to logon share throws SmbException
    @Test
    @DisplayName("treeConnectLogon throws SmbException when underlying call fails")
    void treeConnectLogon_throws() throws SmbException {
        doThrow(new SmbException("logon failed")).when(session).treeConnectLogon();
        SmbException ex = assertThrows(SmbException.class, () -> session.treeConnectLogon());
        assertTrue(ex.getMessage().contains("failed"));
        verify(session).treeConnectLogon();
    }

    // Happy path: getSmbTree returns a tree and receives correct args
    @Test
    @DisplayName("getSmbTree returns tree and captures arguments")
    void getSmbTree_happy() {
        when(session.getSmbTree(anyString(), anyString())).thenReturn(tree);

        String share = "share";
        String svc = "A:"; // service string example (e.g., DISK, IPC, or other)
        SmbTree result = session.getSmbTree(share, svc);

        assertSame(tree, result);

        ArgumentCaptor<String> shareCap = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> svcCap = ArgumentCaptor.forClass(String.class);
        verify(session).getSmbTree(shareCap.capture(), svcCap.capture());
        assertEquals(share, shareCap.getValue());
        assertEquals(svc, svcCap.getValue());
    }

    // Edge/invalid inputs: null or empty share/service cause IllegalArgumentException (mocked)
    @ParameterizedTest
    @DisplayName("getSmbTree invalid inputs (null/empty) throw IllegalArgumentException")
    @CsvSource({ ",service", // null share
            " ,service", // empty share
            "share,", // null service
            "share, " // empty service
    })
    void getSmbTree_invalid(String share, String service) {
        doThrow(new IllegalArgumentException("invalid share/service")).when(session).getSmbTree(eq(share), eq(service));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> session.getSmbTree(share, service));
        assertTrue(ex.getMessage().contains("invalid"));
        verify(session).getSmbTree(eq(share), eq(service));
    }

    // Edge: unknown service returns null per stub
    @Test
    @DisplayName("getSmbTree unknown service returns null as stubbed")
    void getSmbTree_unknownService() {
        when(session.getSmbTree(eq("share"), eq("UNKNOWN"))).thenReturn(null);
        assertNull(session.getSmbTree("share", "UNKNOWN"));
        verify(session).getSmbTree("share", "UNKNOWN");
    }

    // Happy path: reauthenticate completes without exception
    @Test
    @DisplayName("reauthenticate performs call without exception")
    void reauthenticate_happy() throws CIFSException {
        session.reauthenticate();
        verify(session).reauthenticate();
    }

    // Error propagation: reauthenticate throws CIFSException
    @Test
    @DisplayName("reauthenticate throws CIFSException when underlying call fails")
    void reauthenticate_throws() throws CIFSException {
        doThrow(new CIFSException("reauth failed")).when(session).reauthenticate();
        CIFSException ex = assertThrows(CIFSException.class, () -> session.reauthenticate());
        assertTrue(ex.getMessage().contains("failed"));
        verify(session).reauthenticate();
    }
}
