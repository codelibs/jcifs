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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class SmbTreeTest {

    @Mock
    private SmbSession session;

    @Mock
    private SmbTransport transport;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        // Setup transport fields that are accessed directly
        transport.tconHostName = "testHost";
        // Setup session.transport field (accessed directly in SmbTree)
        session.transport = transport;
        // Setup session to return transport via method call
        when(session.transport()).thenReturn(transport);
    }

    @Test
    void testConstructor() {
        // Test constructor with a specific service
        SmbTree tree = new SmbTree(session, "testShare", "testService");
        assertEquals("TESTSHARE", tree.share);
        assertEquals("testService", tree.service);
        assertEquals(0, tree.connectionState);

        // Test constructor with null service
        tree = new SmbTree(session, "testShare", null);
        assertEquals("TESTSHARE", tree.share);
        assertEquals("?????", tree.service);
        assertEquals(0, tree.connectionState);

        // Test constructor with service starting with "??"
        tree = new SmbTree(session, "testShare", "??service");
        assertEquals("TESTSHARE", tree.share);
        assertEquals("?????", tree.service);
        assertEquals(0, tree.connectionState);
    }

    @Test
    void testMatches() {
        SmbTree tree = new SmbTree(session, "testShare", "testService");

        // Test matching share and service (case insensitive)
        assertTrue(tree.matches("testShare", "testService"));
        assertTrue(tree.matches("TESTSHARE", "testService"));
        assertTrue(tree.matches("testshare", "TESTSERVICE"));

        // Test matching share with null service
        assertTrue(tree.matches("testShare", null));

        // Test matching share with service starting with "??"
        assertTrue(tree.matches("testShare", "??otherService"));

        // Test non-matching share
        assertFalse(tree.matches("otherShare", "testService"));

        // Test non-matching service
        assertFalse(tree.matches("testShare", "otherService"));
    }

    @Test
    void testEquals() {
        SmbTree tree1 = new SmbTree(session, "testShare", "testService");
        SmbTree tree2 = new SmbTree(session, "testShare", "testService");
        SmbTree tree3 = new SmbTree(session, "otherShare", "testService");
        SmbTree tree4 = new SmbTree(session, "testShare", "otherService");

        // Test equal trees (same share and service)
        assertEquals(tree1, tree2);

        // Test non-equal trees (different share)
        assertNotEquals(tree1, tree3);

        // Test non-equal trees (different service)
        assertNotEquals(tree1, tree4);

        // Test with different object type
        assertNotEquals(tree1, new Object());
        
        // Test with null
        assertNotEquals(tree1, null);
    }

    @Test
    void testToString() {
        SmbTree tree = new SmbTree(session, "testShare", "testService");
        tree.tid = 123;
        tree.inDfs = true;
        tree.inDomainDfs = false;
        tree.connectionState = 2;

        String result = tree.toString();
        // Verify the toString contains the expected information
        assertTrue(result.contains("TESTSHARE"));
        assertTrue(result.contains("testService"));
        assertTrue(result.contains("123"));
        assertTrue(result.contains("2"));
    }

    @Test
    void testTreeConnectAndDisconnect() throws Exception {
        SmbTree tree = new SmbTree(session, "testShare", "testService");
        
        // Mock transport.connect() to succeed
        doNothing().when(transport).connect();
        
        // Setup response for tree connect
        doAnswer(invocation -> {
            ServerMessageBlock request = invocation.getArgument(0);
            ServerMessageBlock response = invocation.getArgument(1);
            if (request instanceof SmbComTreeConnectAndX && response instanceof SmbComTreeConnectAndXResponse) {
                SmbComTreeConnectAndXResponse treeResponse = (SmbComTreeConnectAndXResponse) response;
                treeResponse.tid = 456;
                treeResponse.service = "testService";
                treeResponse.shareIsInDfs = true;
            }
            return null;
        }).when(session).send(any(ServerMessageBlock.class), any(ServerMessageBlock.class));

        // Test tree connect
        tree.treeConnect(null, null);
        
        assertEquals(2, tree.connectionState);
        assertEquals(456, tree.tid);
        assertEquals("testService", tree.service);
        assertTrue(tree.inDfs);
        
        // Test tree disconnect  
        tree.treeDisconnect(false);
        assertEquals(0, tree.connectionState);
    }

    @Test
    void testTreeConnectFailure() throws Exception {
        SmbTree tree = new SmbTree(session, "testShare", "testService");
        
        // Mock transport.connect() to succeed
        doNothing().when(transport).connect();
        
        // Simulate failed tree connect
        doThrow(new SmbException("Connection failed"))
            .when(session).send(any(ServerMessageBlock.class), any(ServerMessageBlock.class));
        
        assertThrows(SmbException.class, () -> tree.treeConnect(null, null));
        // After failure, state should be reset to disconnected
        assertEquals(0, tree.connectionState);
    }

    @Test
    void testSend() throws SmbException {
        SmbTree tree = new SmbTree(session, "testShare", "A:");
        tree.connectionState = 2; // Connected state
        tree.tid = 123;
        
        // Create real request and response objects since they're not interfaces
        ServerMessageBlock request = new SmbComOpenAndX("testfile.txt", 0x01, 0, null);
        ServerMessageBlock response = new SmbComOpenAndXResponse();
        
        // Execute send
        tree.send(request, response);
        
        // Verify session.send was called and tid was set
        verify(session).send(request, response);
        assertEquals(123, request.tid);
    }

    @Test
    void testSendWithDfs() throws SmbException {
        SmbTree tree = new SmbTree(session, "testShare", "A:");
        tree.connectionState = 2; // Connected state
        tree.tid = 123;
        tree.inDfs = true;
        
        // Create request with path
        ServerMessageBlock request = new SmbComOpenAndX("\\testPath", 0x01, 0, null);
        ServerMessageBlock response = new SmbComOpenAndXResponse();
        
        // Execute send
        tree.send(request, response);
        
        // Verify session.send was called
        verify(session).send(request, response);
        assertEquals(123, request.tid);
        // For A: service with DFS, path should be modified (share name is uppercased)
        assertEquals("\\testHost\\TESTSHARE\\testPath", request.path);
        assertEquals(ServerMessageBlock.FLAGS2_RESOLVE_PATHS_IN_DFS, request.flags2 & ServerMessageBlock.FLAGS2_RESOLVE_PATHS_IN_DFS);
    }
    
    @Test
    void testSendWithDfsIpcService() throws SmbException {
        SmbTree tree = new SmbTree(session, "testShare", "IPC");
        tree.connectionState = 2; // Connected state
        tree.tid = 123;
        tree.inDfs = true;
        
        // Create request with path
        ServerMessageBlock request = new SmbComOpenAndX("\\testPath", 0x01, 0, null);
        ServerMessageBlock response = new SmbComOpenAndXResponse();
        
        // Execute send
        tree.send(request, response);
        
        // Verify session.send was called
        verify(session).send(request, response);
        assertEquals(123, request.tid);
        // For IPC service, path should not be modified even with DFS
        assertEquals("\\testPath", request.path);
    }

    @Test
    void testSendWithNetworkNameDeleted() throws SmbException {
        SmbTree tree = new SmbTree(session, "testShare", "A:");
        tree.connectionState = 2; // Connected state
        tree.tid = 123;
        
        // Create request and response
        ServerMessageBlock request = new SmbComOpenAndX("testfile.txt", 0x01, 0, null);
        ServerMessageBlock response = new SmbComOpenAndXResponse();
        
        // Simulate network name deleted error
        SmbException networkDeletedError = new SmbException(SmbException.NT_STATUS_NETWORK_NAME_DELETED, false);
        doThrow(networkDeletedError).when(session).send(any(ServerMessageBlock.class), any(ServerMessageBlock.class));
        
        // Execute and verify exception is thrown
        assertThrows(SmbException.class, () -> tree.send(request, response));
        // After network name deleted error, tree should be disconnected
        assertEquals(0, tree.connectionState);
    }
    
    @Test
    void testSendInvalidOperationForNonDiskService() throws SmbException {
        SmbTree tree = new SmbTree(session, "testShare", "PRINT");
        tree.connectionState = 2; // Connected state
        tree.tid = 123;
        
        // Create request with command not allowed for PRINT service
        ServerMessageBlock request = new SmbComDelete("testfile.txt");
        ServerMessageBlock response = new SmbComBlankResponse();
        
        // Should throw exception for invalid operation
        assertThrows(SmbException.class, () -> tree.send(request, response));
    }
    
    @Test
    void testTreeConnectWithWaitInterrupted() throws Exception {
        // Create a tree and simulate concurrent connection attempt
        SmbTree tree = new SmbTree(session, "testShare", "testService");
        
        // Mock transport.connect() to throw RuntimeException wrapping InterruptedException
        doThrow(new RuntimeException(new InterruptedException("Interrupted"))).when(transport).connect();
        
        // Should throw exception due to interrupted wait
        assertThrows(RuntimeException.class, () -> tree.treeConnect(null, null));
    }
}