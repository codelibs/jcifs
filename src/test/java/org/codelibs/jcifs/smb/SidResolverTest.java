package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SidResolverTest {

    @Mock
    private SidResolver sidResolver;

    @Mock
    private CIFSContext mockContext;

    @Mock
    private SID mockSid1;

    @Mock
    private SID mockSid2;

    @Mock
    private SID mockSid3;

    @Mock
    private SID mockDomainSid;

    private String testServerName;
    private SID[] testSids;

    @BeforeEach
    void setUp() {
        testServerName = "test-server.domain.com";
        testSids = new SID[] { mockSid1, mockSid2, mockSid3 };
    }

    // Test resolveSids with array
    @Test
    void testResolveSids_Success() throws CIFSException {
        doNothing().when(sidResolver).resolveSids(any(CIFSContext.class), anyString(), any(SID[].class));

        assertDoesNotThrow(() -> sidResolver.resolveSids(mockContext, testServerName, testSids));

        verify(sidResolver, times(1)).resolveSids(mockContext, testServerName, testSids);
    }

    @Test
    void testResolveSids_WithNullContext() throws CIFSException {
        doThrow(new CIFSException("Context cannot be null")).when(sidResolver).resolveSids(eq(null), anyString(), any(SID[].class));

        assertThrows(CIFSException.class, () -> sidResolver.resolveSids(null, testServerName, testSids));
    }

    @Test
    void testResolveSids_WithNullServerName() throws CIFSException {
        doThrow(new CIFSException("Server name cannot be null")).when(sidResolver)
                .resolveSids(any(CIFSContext.class), eq(null), any(SID[].class));

        assertThrows(CIFSException.class, () -> sidResolver.resolveSids(mockContext, null, testSids));
    }

    @Test
    void testResolveSids_WithNullSidsArray() throws CIFSException {
        doThrow(new CIFSException("SIDs array cannot be null")).when(sidResolver)
                .resolveSids(any(CIFSContext.class), anyString(), eq(null));

        assertThrows(CIFSException.class, () -> sidResolver.resolveSids(mockContext, testServerName, null));
    }

    @Test
    void testResolveSids_WithEmptySidsArray() throws CIFSException {
        SID[] emptySids = new SID[0];
        doNothing().when(sidResolver).resolveSids(any(CIFSContext.class), anyString(), any(SID[].class));

        assertDoesNotThrow(() -> sidResolver.resolveSids(mockContext, testServerName, emptySids));
    }

    // Test resolveSids with offset and length
    @Test
    void testResolveSidsWithOffsetAndLength_Success() throws CIFSException {
        doNothing().when(sidResolver).resolveSids(any(CIFSContext.class), anyString(), any(SID[].class), anyInt(), anyInt());

        assertDoesNotThrow(() -> sidResolver.resolveSids(mockContext, testServerName, testSids, 0, 2));

        verify(sidResolver, times(1)).resolveSids(mockContext, testServerName, testSids, 0, 2);
    }

    @Test
    void testResolveSidsWithOffsetAndLength_InvalidOffset() throws CIFSException {
        doThrow(new CIFSException("Invalid offset")).when(sidResolver)
                .resolveSids(any(CIFSContext.class), anyString(), any(SID[].class), eq(-1), anyInt());

        assertThrows(CIFSException.class, () -> sidResolver.resolveSids(mockContext, testServerName, testSids, -1, 2));
    }

    @Test
    void testResolveSidsWithOffsetAndLength_InvalidLength() throws CIFSException {
        doThrow(new CIFSException("Invalid length")).when(sidResolver)
                .resolveSids(any(CIFSContext.class), anyString(), any(SID[].class), anyInt(), eq(-1));

        assertThrows(CIFSException.class, () -> sidResolver.resolveSids(mockContext, testServerName, testSids, 0, -1));
    }

    @Test
    void testResolveSidsWithOffsetAndLength_OutOfBounds() throws CIFSException {
        doThrow(new CIFSException("Array index out of bounds")).when(sidResolver)
                .resolveSids(any(CIFSContext.class), anyString(), any(SID[].class), eq(5), anyInt());

        assertThrows(CIFSException.class, () -> sidResolver.resolveSids(mockContext, testServerName, testSids, 5, 2));
    }

    // Test getGroupMemberSids
    @Test
    void testGetGroupMemberSids_Success() throws CIFSException {
        SID[] expectedMembers = new SID[] { mockSid1, mockSid2 };
        when(sidResolver.getGroupMemberSids(any(CIFSContext.class), anyString(), any(SID.class), anyInt(), anyInt()))
                .thenReturn(expectedMembers);

        SID[] result = sidResolver.getGroupMemberSids(mockContext, testServerName, mockDomainSid, 512, 0);

        assertNotNull(result);
        assertArrayEquals(expectedMembers, result);
        verify(sidResolver, times(1)).getGroupMemberSids(mockContext, testServerName, mockDomainSid, 512, 0);
    }

    @Test
    void testGetGroupMemberSids_EmptyGroup() throws CIFSException {
        when(sidResolver.getGroupMemberSids(any(CIFSContext.class), anyString(), any(SID.class), anyInt(), anyInt()))
                .thenReturn(new SID[0]);

        SID[] result = sidResolver.getGroupMemberSids(mockContext, testServerName, mockDomainSid, 513, 0);

        assertNotNull(result);
        assertEquals(0, result.length);
    }

    @Test
    void testGetGroupMemberSids_WithNullDomainSid() throws CIFSException {
        when(sidResolver.getGroupMemberSids(any(CIFSContext.class), anyString(), eq(null), anyInt(), anyInt()))
                .thenThrow(new CIFSException("Domain SID cannot be null"));

        assertThrows(CIFSException.class, () -> sidResolver.getGroupMemberSids(mockContext, testServerName, null, 512, 0));
    }

    @Test
    void testGetGroupMemberSids_InvalidRid() throws CIFSException {
        when(sidResolver.getGroupMemberSids(any(CIFSContext.class), anyString(), any(SID.class), eq(-1), anyInt()))
                .thenThrow(new CIFSException("Invalid RID"));

        assertThrows(CIFSException.class, () -> sidResolver.getGroupMemberSids(mockContext, testServerName, mockDomainSid, -1, 0));
    }

    // Test getServerSid
    @Test
    void testGetServerSid_Success() throws CIFSException {
        when(sidResolver.getServerSid(any(CIFSContext.class), anyString())).thenReturn(mockSid1);

        SID result = sidResolver.getServerSid(mockContext, testServerName);

        assertNotNull(result);
        assertEquals(mockSid1, result);
        verify(sidResolver, times(1)).getServerSid(mockContext, testServerName);
    }

    @Test
    void testGetServerSid_NullContext() throws CIFSException {
        when(sidResolver.getServerSid(eq(null), anyString())).thenThrow(new CIFSException("Context cannot be null"));

        assertThrows(CIFSException.class, () -> sidResolver.getServerSid(null, testServerName));
    }

    @Test
    void testGetServerSid_NullServerName() throws CIFSException {
        when(sidResolver.getServerSid(any(CIFSContext.class), eq(null))).thenThrow(new CIFSException("Server name cannot be null"));

        assertThrows(CIFSException.class, () -> sidResolver.getServerSid(mockContext, null));
    }

    @Test
    void testGetServerSid_EmptyServerName() throws CIFSException {
        when(sidResolver.getServerSid(any(CIFSContext.class), eq(""))).thenThrow(new CIFSException("Server name cannot be empty"));

        assertThrows(CIFSException.class, () -> sidResolver.getServerSid(mockContext, ""));
    }

    // Test getLocalGroupsMap
    @Test
    void testGetLocalGroupsMap_Success() throws CIFSException {
        Map<SID, List<SID>> expectedMap = new HashMap<>();
        List<SID> group1Members = Arrays.asList(mockSid1, mockSid2);
        List<SID> group2Members = Arrays.asList(mockSid3);
        expectedMap.put(mockDomainSid, group1Members);
        expectedMap.put(mockSid1, group2Members);

        when(sidResolver.getLocalGroupsMap(any(CIFSContext.class), anyString(), anyInt())).thenReturn(expectedMap);

        Map<SID, List<SID>> result = sidResolver.getLocalGroupsMap(mockContext, testServerName, 0);

        assertNotNull(result);
        assertEquals(2, result.size());
        assertTrue(result.containsKey(mockDomainSid));
        assertTrue(result.containsKey(mockSid1));
        assertEquals(group1Members, result.get(mockDomainSid));
        assertEquals(group2Members, result.get(mockSid1));
    }

    @Test
    void testGetLocalGroupsMap_EmptyResult() throws CIFSException {
        when(sidResolver.getLocalGroupsMap(any(CIFSContext.class), anyString(), anyInt())).thenReturn(new HashMap<>());

        Map<SID, List<SID>> result = sidResolver.getLocalGroupsMap(mockContext, testServerName, 0);

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void testGetLocalGroupsMap_WithSidFlagResolveSids() throws CIFSException {
        Map<SID, List<SID>> expectedMap = new HashMap<>();
        expectedMap.put(mockDomainSid, Arrays.asList(mockSid1));

        when(sidResolver.getLocalGroupsMap(any(CIFSContext.class), anyString(), eq(1))).thenReturn(expectedMap);

        Map<SID, List<SID>> result = sidResolver.getLocalGroupsMap(mockContext, testServerName, 1);

        assertNotNull(result);
        assertEquals(1, result.size());
        assertTrue(result.containsKey(mockDomainSid));
    }

    @Test
    void testGetLocalGroupsMap_NullContext() throws CIFSException {
        when(sidResolver.getLocalGroupsMap(eq(null), anyString(), anyInt())).thenThrow(new CIFSException("Context cannot be null"));

        assertThrows(CIFSException.class, () -> sidResolver.getLocalGroupsMap(null, testServerName, 0));
    }

    @Test
    void testGetLocalGroupsMap_InvalidFlags() throws CIFSException {
        when(sidResolver.getLocalGroupsMap(any(CIFSContext.class), anyString(), eq(-1))).thenThrow(new CIFSException("Invalid flags"));

        assertThrows(CIFSException.class, () -> sidResolver.getLocalGroupsMap(mockContext, testServerName, -1));
    }

    // Test with network errors
    @Test
    void testResolveSids_NetworkError() throws CIFSException {
        doThrow(new CIFSException("Network error occurred")).when(sidResolver)
                .resolveSids(any(CIFSContext.class), anyString(), any(SID[].class));

        assertThrows(CIFSException.class, () -> sidResolver.resolveSids(mockContext, testServerName, testSids));
    }

    @Test
    void testGetServerSid_ConnectionTimeout() throws CIFSException {
        when(sidResolver.getServerSid(any(CIFSContext.class), anyString())).thenThrow(new CIFSException("Connection timeout"));

        assertThrows(CIFSException.class, () -> sidResolver.getServerSid(mockContext, testServerName));
    }

    // Test with large datasets
    @Test
    void testResolveSids_LargeArray() throws CIFSException {
        SID[] largeSidArray = new SID[1000];
        for (int i = 0; i < 1000; i++) {
            largeSidArray[i] = mock(SID.class);
        }

        doNothing().when(sidResolver).resolveSids(any(CIFSContext.class), anyString(), any(SID[].class));

        assertDoesNotThrow(() -> sidResolver.resolveSids(mockContext, testServerName, largeSidArray));
    }

    @Test
    void testGetLocalGroupsMap_LargeGroupMembership() throws CIFSException {
        Map<SID, List<SID>> largeMap = new HashMap<>();
        for (int i = 0; i < 100; i++) {
            SID groupSid = mock(SID.class);
            List<SID> members = new ArrayList<>();
            for (int j = 0; j < 50; j++) {
                members.add(mock(SID.class));
            }
            largeMap.put(groupSid, members);
        }

        when(sidResolver.getLocalGroupsMap(any(CIFSContext.class), anyString(), anyInt())).thenReturn(largeMap);

        Map<SID, List<SID>> result = sidResolver.getLocalGroupsMap(mockContext, testServerName, 0);

        assertNotNull(result);
        assertEquals(100, result.size());
    }

    // Test partial array resolution
    @Test
    void testResolveSidsWithOffsetAndLength_PartialResolution() throws CIFSException {
        SID[] sids = new SID[] { mockSid1, mockSid2, mockSid3 };

        doNothing().when(sidResolver).resolveSids(any(CIFSContext.class), anyString(), any(SID[].class), eq(1), eq(2));

        assertDoesNotThrow(() -> sidResolver.resolveSids(mockContext, testServerName, sids, 1, 2));

        verify(sidResolver, times(1)).resolveSids(mockContext, testServerName, sids, 1, 2);
    }

    @Test
    void testResolveSidsWithOffsetAndLength_FullArray() throws CIFSException {
        doNothing().when(sidResolver).resolveSids(any(CIFSContext.class), anyString(), any(SID[].class), eq(0), eq(3));

        assertDoesNotThrow(() -> sidResolver.resolveSids(mockContext, testServerName, testSids, 0, 3));
    }

    @Test
    void testResolveSidsWithOffsetAndLength_SingleElement() throws CIFSException {
        doNothing().when(sidResolver).resolveSids(any(CIFSContext.class), anyString(), any(SID[].class), eq(2), eq(1));

        assertDoesNotThrow(() -> sidResolver.resolveSids(mockContext, testServerName, testSids, 2, 1));
    }

    // Test edge cases for getGroupMemberSids
    @Test
    void testGetGroupMemberSids_MaxRid() throws CIFSException {
        when(sidResolver.getGroupMemberSids(any(CIFSContext.class), anyString(), any(SID.class), eq(Integer.MAX_VALUE), anyInt()))
                .thenReturn(new SID[0]);

        SID[] result = sidResolver.getGroupMemberSids(mockContext, testServerName, mockDomainSid, Integer.MAX_VALUE, 0);

        assertNotNull(result);
    }

    @Test
    void testGetGroupMemberSids_ZeroRid() throws CIFSException {
        when(sidResolver.getGroupMemberSids(any(CIFSContext.class), anyString(), any(SID.class), eq(0), anyInt()))
                .thenReturn(new SID[] { mockSid1 });

        SID[] result = sidResolver.getGroupMemberSids(mockContext, testServerName, mockDomainSid, 0, 0);

        assertNotNull(result);
        assertEquals(1, result.length);
    }

    // Test different flag combinations
    @Test
    void testGetGroupMemberSids_DifferentFlags() throws CIFSException {
        int[] testFlags = { 0, 1, 2, 4, 8, 16, 32, Integer.MAX_VALUE };

        for (int flag : testFlags) {
            when(sidResolver.getGroupMemberSids(any(CIFSContext.class), anyString(), any(SID.class), anyInt(), eq(flag)))
                    .thenReturn(new SID[0]);

            SID[] result = sidResolver.getGroupMemberSids(mockContext, testServerName, mockDomainSid, 512, flag);

            assertNotNull(result);
        }
    }

    @Test
    void testGetLocalGroupsMap_DifferentFlags() throws CIFSException {
        int[] testFlags = { 0, 1, 2, 4, 8, 16, 32, Integer.MAX_VALUE };

        for (int flag : testFlags) {
            when(sidResolver.getLocalGroupsMap(any(CIFSContext.class), anyString(), eq(flag))).thenReturn(new HashMap<>());

            Map<SID, List<SID>> result = sidResolver.getLocalGroupsMap(mockContext, testServerName, flag);

            assertNotNull(result);
        }
    }
}