package jcifs.smb1.dcerpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import jcifs.smb1.dcerpc.ndr.NdrBuffer;
import jcifs.smb1.dcerpc.ndr.NdrException;

/**
 * Unit tests for {@link DcerpcMessage}. The tests exercise flag handling,
 * result extraction, header encoding/decoding, and the round-trip of an
 * encode/decode operation.
 */
public class DcerpcMessageTest {

    /**
     * A trivial concrete subclass used for testing. It simply writes a
     * single small value in {@code encode_in} and reads it in
     * {@code decode_out}.
     */
    private static class TestMessage extends DcerpcMessage {
        int decodedValue = 0;

        TestMessage() {
            /* nothing */
        }

        @Override
        public int getOpnum() {
            return 0x1234;
        }

        @Override
        public void encode_in(NdrBuffer buf) throws NdrException {
            buf.enc_ndr_small(0xAB);
        }

        @Override
        public void decode_out(NdrBuffer buf) throws NdrException {
            decodedValue = buf.dec_ndr_small();
        }
    }

    /* --- flag handling -------------------------------- */
    @Test
    void testFlagSetAndUnset() {
        TestMessage m = new TestMessage();
        int FLAG_A = 0x01;
        int FLAG_B = 0x02;
        assertFalse(m.isFlagSet(FLAG_A));
        m.setFlag(FLAG_A);
        assertTrue(m.isFlagSet(FLAG_A));
        // unset correctly removes the flag
        m.unsetFlag(FLAG_A);
        assertFalse(m.isFlagSet(FLAG_A));
        // Test another flag
        m.setFlag(FLAG_B);
        assertTrue(m.isFlagSet(FLAG_B));
        m.unsetFlag(FLAG_B);
        assertFalse(m.isFlagSet(FLAG_B));
    }

    private static final class ResultMsg extends TestMessage {
        void setResult(int r) {
            this.result = r;
        }
    }

    @Test
    void testGetResult() {
        ResultMsg m = new ResultMsg();
        assertNull(m.getResult());
        m.setResult(0xDEAD);
        DcerpcException e = m.getResult();
        assertEquals(0xDEAD, e.getErrorCode());
    }

    @Test
    void testEncodeHeaderAndDecodeHeader() throws Exception {
        TestMessage m = new TestMessage();
        m.ptype = 0; // request
        m.flags = 0x05;
        m.alloc_hint = 0;
        NdrBuffer buf = new NdrBuffer(new byte[1024], 0);
        m.encode(buf);
        // decode back
        buf.setIndex(0);
        m.decode_header(buf);
        assertEquals(0, m.ptype);
    }

    @Test
    void testDecodeHeaderInvalidVersion() {
        NdrBuffer buf = new NdrBuffer(new byte[10], 0);
        buf.enc_ndr_small(4); // bad major
        buf.enc_ndr_small(0);
        TestMessage msg = new TestMessage();
        assertThrows(NdrException.class, () -> msg.decode_header(buf));
    }

    @Test
    void testRoundTripEncodeDecodeForRequestType() throws Exception {
        TestMessage m = new TestMessage();
        m.ptype = 0; // Request type
        NdrBuffer buf = new NdrBuffer(new byte[1024], 0);
        m.encode(buf);

        buf.setIndex(0);
        // Decode will throw exception as ptype 0 is not a valid response type
        assertThrows(NdrException.class, () -> m.decode(buf));
    }

    @Test
    void testRoundTripEncodeDecodeForResponseType() throws Exception {
        // Create a properly formatted response message
        NdrBuffer buf = new NdrBuffer(new byte[1024], 0);

        // Manually encode a response header
        buf.enc_ndr_small(5); // RPC version
        buf.enc_ndr_small(0); // minor version
        buf.enc_ndr_small(2); // ptype = 2 (Response)
        buf.enc_ndr_small(0); // flags
        buf.enc_ndr_long(0x00000010); // data representation
        buf.enc_ndr_short(20); // length
        buf.enc_ndr_short(0); // auth length
        buf.enc_ndr_long(0); // call_id

        // Response body
        buf.enc_ndr_long(4); // alloc_hint
        buf.enc_ndr_short(0); // context_id
        buf.enc_ndr_short(0); // cancel_count
        buf.enc_ndr_small(0xAB); // test data for decode_out

        // Decode
        buf.setIndex(0);
        TestMessage m = new TestMessage();
        m.decode(buf);

        assertEquals(2, m.ptype);
        assertEquals(0xAB, m.decodedValue);
    }

    @Test
    void testRoundTripEncodeDecodeForFaultType() throws Exception {
        // Create a properly formatted fault message
        NdrBuffer buf = new NdrBuffer(new byte[1024], 0);

        // Manually encode a fault header
        buf.enc_ndr_small(5); // RPC version
        buf.enc_ndr_small(0); // minor version
        buf.enc_ndr_small(3); // ptype = 3 (Fault)
        buf.enc_ndr_small(0); // flags
        buf.enc_ndr_long(0x00000010); // data representation
        buf.enc_ndr_short(20); // length
        buf.enc_ndr_short(0); // auth length
        buf.enc_ndr_long(0); // call_id

        // Fault body
        buf.enc_ndr_long(0); // alloc_hint
        buf.enc_ndr_short(0); // context_id
        buf.enc_ndr_short(0); // cancel_count
        buf.enc_ndr_long(0xDEADBEEF); // fault status

        // Decode
        buf.setIndex(0);
        TestMessage m = new TestMessage();
        m.decode(buf);

        assertEquals(3, m.ptype);
        assertEquals(0xDEADBEEF, m.result);
        assertNotNull(m.getResult());
    }

    @Test
    void testAllocateHintCalculation() throws Exception {
        TestMessage m = new TestMessage();
        m.ptype = 0;
        NdrBuffer buf = new NdrBuffer(new byte[1024], 0);
        m.encode(buf);
        assertTrue(m.alloc_hint > 0);
    }

    @Test
    void testEncodeWritesCorrectHeader() throws Exception {
        TestMessage m = new TestMessage();
        m.ptype = 0;
        m.flags = 0x05;
        m.call_id = 0x123;

        NdrBuffer buf = new NdrBuffer(new byte[1024], 0);
        m.encode(buf);

        // Reset to read what was written
        buf.setIndex(0);

        // Verify header was written correctly
        assertEquals(5, buf.dec_ndr_small()); // RPC version
        assertEquals(0, buf.dec_ndr_small()); // minor version  
        assertEquals(0, buf.dec_ndr_small()); // ptype
        assertEquals(0x05, buf.dec_ndr_small()); // flags
        assertEquals(0x00000010, buf.dec_ndr_long()); // data representation
        assertTrue(buf.dec_ndr_short() > 0); // length
        assertEquals(0, buf.dec_ndr_short()); // auth length
        assertEquals(0x123, buf.dec_ndr_long()); // call_id
    }

    @Test
    void testEncodeWithDifferentFlags() throws Exception {
        for (int flag : new int[] { 0, 0xFF, 0x01, 0x80 }) {
            TestMessage m = new TestMessage();
            m.ptype = 0;
            m.flags = flag;

            NdrBuffer buf = new NdrBuffer(new byte[1024], 0);
            m.encode(buf);

            // Reset and skip to flags field
            buf.setIndex(3);
            assertEquals(flag, buf.dec_ndr_small());
        }
    }
}
