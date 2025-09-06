package org.codelibs.jcifs.smb.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.SIDObject;
import org.codelibs.jcifs.smb.dcerpc.rpc.sid_t;
import org.junit.jupiter.api.Test;

class LsarSidArrayXTest {

    @Test
    void testConstructorWithJcifsSIDArrayAndUnwrap() {
        // Create mock SIDObject objects
        SIDObject mockSid1 = mock(SIDObject.class);
        SIDObject mockSid2 = mock(SIDObject.class);

        // Mock the unwrap method to return a sid_t instance
        sid_t sidT1 = new sid_t();
        sid_t sidT2 = new sid_t();
        when(mockSid1.unwrap(sid_t.class)).thenReturn(sidT1);
        when(mockSid2.unwrap(sid_t.class)).thenReturn(sidT2);

        org.codelibs.jcifs.smb.SID[] sids = { mockSid1, mockSid2 };
        LsarSidArrayX lsarSidArrayX = new LsarSidArrayX(sids);

        // Verify num_sids
        assertEquals(2, lsarSidArrayX.num_sids, "num_sids should match the array length");

        // Verify sids array and its contents
        assertNotNull(lsarSidArrayX.sids, "sids array should not be null");
        assertEquals(2, lsarSidArrayX.sids.length, "sids array length should match");
        assertEquals(sidT1, lsarSidArrayX.sids[0].sid, "First SIDObject should be unwrapped correctly");
        assertEquals(sidT2, lsarSidArrayX.sids[1].sid, "Second SIDObject should be unwrapped correctly");
    }

    @Test
    void testConstructorWithJcifsSIDArrayDirectAssignment() {
        // Create mock SIDObject objects
        SIDObject mockSid1 = mock(SIDObject.class);
        SIDObject mockSid2 = mock(SIDObject.class);

        SIDObject[] sids = { mockSid1, mockSid2 };
        LsarSidArrayX lsarSidArrayX = new LsarSidArrayX(sids);

        // Verify num_sids
        assertEquals(2, lsarSidArrayX.num_sids, "num_sids should match the array length");

        // Verify sids array and its contents
        assertNotNull(lsarSidArrayX.sids, "sids array should not be null");
        assertEquals(2, lsarSidArrayX.sids.length, "sids array length should match");
        assertEquals(mockSid1, lsarSidArrayX.sids[0].sid, "First SIDObject should be assigned directly");
        assertEquals(mockSid2, lsarSidArrayX.sids[1].sid, "Second SIDObject should be assigned directly");
    }

    @Test
    void testConstructorWithEmptySIDArray() {
        org.codelibs.jcifs.smb.SID[] sids = {};
        LsarSidArrayX lsarSidArrayX = new LsarSidArrayX(sids);

        // Verify num_sids
        assertEquals(0, lsarSidArrayX.num_sids, "num_sids should be 0 for an empty array");

        // Verify sids array
        assertNotNull(lsarSidArrayX.sids, "sids array should not be null for an empty array");
        assertEquals(0, lsarSidArrayX.sids.length, "sids array length should be 0 for an empty array");
    }

    @Test
    void testConstructorWithNullSIDArray() {
        org.codelibs.jcifs.smb.SID[] sids = null;
        // Expect NullPointerException when passing a null array to the constructor
        assertThrows(NullPointerException.class, () -> new LsarSidArrayX(sids),
                "Should throw NullPointerException when sids array is null");
    }
}
