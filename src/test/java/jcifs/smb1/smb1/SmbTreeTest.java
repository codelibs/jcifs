/*
 * Copyright 2024 The JCIFS Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package jcifs.smb1.smb1;

import jcifs.smb1.SmbException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SmbTreeTest {

    @Mock
    private SmbSession session;

    @Mock
    private SmbTransport transport;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(session.transport()).thenReturn(transport);
        when(transport.tconHostName).thenReturn("testHost");
        when(transport.log).thenReturn(new PrintStream(System.out));
    }

    @Test
    void testConstructor() {
        // Test constructor with a specific service
        SmbTree tree = new SmbTree(session, "testShare", "testService");
        assertEquals("TESTSHARE", tree.share);
        assertEquals("testService", tree.service);
        assertEquals(0, tree.connectionState);

        // Test constructor with a null service
        tree = new SmbTree(session, "testShare", null);
        assertEquals("TESTSHARE", tree.share);
        assertEquals("?????", tree.service);
        assertEquals(0, tree.connectionState);

        // Test constructor with a service starting with "??"
        tree = new SmbTree(session, "testShare", "??service");
        assertEquals("TESTSHARE", tree.share);
        assertEquals("?????", tree.service);
        assertEquals(0, tree.connectionState);
    }

    @Test
    void testMatches() {
        SmbTree tree = new SmbTree(session, "testShare", "testService");

        // Test with matching share and service
        assertTrue(tree.matches("testShare", "testService"));

        // Test with matching share and null service
        assertTrue(tree.matches("testShare", null));

        // Test with matching share and service starting with "??"
        assertTrue(tree.matches("testShare", "??otherService"));

        // Test with non-matching share
        assertFalse(tree.matches("otherShare", "testService"));

        // Test with non-matching service
        assertFalse(tree.matches("testShare", "otherService"));
    }

    @Test
    void testEquals() {
        SmbTree tree1 = new SmbTree(session, "testShare", "testService");
        SmbTree tree2 = new SmbTree(session, "testShare", "testService");
        SmbTree tree3 = new SmbTree(session, "otherShare", "testService");

        // Test with equal objects
        assertEquals(tree1, tree2);

        // Test with non-equal objects
        assertNotEquals(tree1, tree3);

        // Test with a different object type
        assertNotEquals(tree1, new Object());
    }

    @Test
    void testToString() {
        SmbTree tree = new SmbTree(session, "testShare", "testService");
        tree.tid = 123;
        tree.inDfs = true;
        tree.inDomainDfs = false;
        tree.connectionState = 2;

        String expected = "SmbTree[share=TESTSHARE,service=testService,tid=123,inDfs=true,inDomainDfs=false,connectionState=2]";
        assertEquals(expected, tree.toString());
    }

    @Test
    void testTreeConnectAndDisconnect() throws SmbException {
        SmbTree tree = new SmbTree(session, "testShare", "testService");

        // Mock the response to the tree connect request
        SmbComTreeConnectAndXResponse response = new SmbComTreeConnectAndXResponse(null);
        response.tid = 456;
        response.service = "testService";
        response.shareIsInDfs = true;

        // Simulate a successful tree connect
        doAnswer(invocation -> {
            SmbComTreeConnectAndXResponse resp = invocation.getArgument(1);
            resp.tid = response.tid;
            resp.service = response.service;
            resp.shareIsInDfs = response.shareIsInDfs;
            return null;
        }).when(session).send(any(SmbComTreeConnectAndX.class), any(SmbComTreeConnectAndXResponse.class));

        tree.treeConnect(null, null);

        assertEquals(2, tree.connectionState);
        assertEquals(456, tree.tid);
        assertEquals("testService", tree.service);
        assertTrue(tree.inDfs);

        // Simulate a successful tree disconnect
        tree.treeDisconnect(false);
        assertEquals(0, tree.connectionState);
    }

    @Test
    void testTreeConnectFailure() throws SmbException {
        SmbTree tree = new SmbTree(session, "testShare", "testService");

        // Simulate a failed tree connect
        doThrow(new SmbException("Connection failed")).when(session).send(any(SmbComTreeConnectAndX.class), any(SmbComTreeConnectAndXResponse.class));

        assertThrows(SmbException.class, () -> tree.treeConnect(null, null));
        assertEquals(0, tree.connectionState);
    }

    @Test
    void testSend() throws SmbException {
        SmbTree tree = new SmbTree(session, "testShare", "A:");
        tree.connectionState = 2; // a connected tree
        tree.tid = 123;

        ServerMessageBlock request = new SmbComOpenAndX();
        ServerMessageBlock response = new SmbComOpenAndXResponse();

        tree.send(request, response);

        verify(session).send(request, response);
        assertEquals(123, request.tid);
    }

    @Test
    void testSendWithDfs() throws SmbException {
        SmbTree tree = new SmbTree(session, "testShare", "A:");
        tree.connectionState = 2; // a connected tree
        tree.tid = 123;
        tree.inDfs = true;

        ServerMessageBlock request = new SmbComOpenAndX();
        request.path = "\testPath";
        ServerMessageBlock response = new SmbComOpenAndXResponse();

        tree.send(request, response);

        verify(session).send(request, response);
        assertEquals(123, request.tid);
        assertEquals("\\testHost\testShare\testPath", request.path);
        assertEquals(ServerMessageBlock.FLAGS2_RESOLVE_PATHS_IN_DFS, request.flags2 & ServerMessageBlock.FLAGS2_RESOLVE_PATHS_IN_DFS);
    }

    @Test
    void testSendWithNetworkNameDeleted() throws SmbException {
        SmbTree tree = new SmbTree(session, "testShare", "A:");
        tree.connectionState = 2; // a connected tree
        tree.tid = 123;

        ServerMessageBlock request = new SmbComOpenAndX();
        ServerMessageBlock response = new SmbComOpenAndXResponse();

        doThrow(new SmbException(SmbException.NT_STATUS_NETWORK_NAME_DELETED, false)).when(session).send(request, response);

        assertThrows(SmbException.class, () -> tree.send(request, response));
        assertEquals(0, tree.connectionState);
    }
}
