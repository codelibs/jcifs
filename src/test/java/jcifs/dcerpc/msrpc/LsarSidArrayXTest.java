package jcifs.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import jcifs.dcerpc.rpc.sid_t;
import jcifs.smb.SID;

class LsarSidArrayXTest {

    @Test
    void testConstructorWithJcifsSIDArrayAndUnwrap() {
        // Create mock SID objects
        SID mockSid1 = mock(SID.class);
        SID mockSid2 = mock(SID.class);

        // Mock the unwrap method to return a sid_t instance
        sid_t sidT1 = new sid_t();
        sid_t sidT2 = new sid_t();
        when(mockSid1.unwrap(sid_t.class)).thenReturn(sidT1);
        when(mockSid2.unwrap(sid_t.class)).thenReturn(sidT2);

        jcifs.SID[] sids = { mockSid1, mockSid2 };
        LsarSidArrayX lsarSidArrayX = new LsarSidArrayX(sids);

        // Verify num_sids
        assertEquals(2, lsarSidArrayX.num_sids, "num_sids should match the array length");

        // Verify sids array and its contents
        assertNotNull(lsarSidArrayX.sids, "sids array should not be null");
        assertEquals(2, lsarSidArrayX.sids.length, "sids array length should match");
        assertEquals(sidT1, lsarSidArrayX.sids[0].sid, "First SID should be unwrapped correctly");
        assertEquals(sidT2, lsarSidArrayX.sids[1].sid, "Second SID should be unwrapped correctly");
    }

    @Test
    void testConstructorWithJcifsSIDArrayDirectAssignment() {
        // Create mock SID objects
        SID mockSid1 = mock(SID.class);
        SID mockSid2 = mock(SID.class);

        SID[] sids = { mockSid1, mockSid2 };
        LsarSidArrayX lsarSidArrayX = new LsarSidArrayX(sids);

        // Verify num_sids
        assertEquals(2, lsarSidArrayX.num_sids, "num_sids should match the array length");

        // Verify sids array and its contents
        assertNotNull(lsarSidArrayX.sids, "sids array should not be null");
        assertEquals(2, lsarSidArrayX.sids.length, "sids array length should match");
        assertEquals(mockSid1, lsarSidArrayX.sids[0].sid, "First SID should be assigned directly");
        assertEquals(mockSid2, lsarSidArrayX.sids[1].sid, "Second SID should be assigned directly");
    }

    @Test
    void testConstructorWithEmptySIDArray() {
        jcifs.SID[] sids = {};
        LsarSidArrayX lsarSidArrayX = new LsarSidArrayX(sids);

        // Verify num_sids
        assertEquals(0, lsarSidArrayX.num_sids, "num_sids should be 0 for an empty array");

        // Verify sids array
        assertNotNull(lsarSidArrayX.sids, "sids array should not be null for an empty array");
        assertEquals(0, lsarSidArrayX.sids.length, "sids array length should be 0 for an empty array");
    }

    @Test
    void testConstructorWithNullSIDArray() {
        jcifs.SID[] sids = null;
        // Expect NullPointerException when passing a null array to the constructor
        assertThrows(NullPointerException.class, () -> new LsarSidArrayX(sids),
                "Should throw NullPointerException when sids array is null");
    }
}
