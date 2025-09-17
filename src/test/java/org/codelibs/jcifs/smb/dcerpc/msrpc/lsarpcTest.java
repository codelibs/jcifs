package org.codelibs.jcifs.smb.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyShort;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.dcerpc.rpc;
import org.codelibs.jcifs.smb.dcerpc.ndr.NdrBuffer;
import org.codelibs.jcifs.smb.dcerpc.ndr.NdrException;
import org.codelibs.jcifs.smb.dcerpc.ndr.NdrSmall;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class lsarpcTest {

    @Mock
    private NdrBuffer mockNdrBuffer;
    @Mock
    private NdrBuffer mockDeferredNdrBuffer;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        // Set the deferred field directly since it's a public field
        mockNdrBuffer.deferred = mockDeferredNdrBuffer;
        // Set up deferred buffer chain to avoid NPE
        mockDeferredNdrBuffer.deferred = mockDeferredNdrBuffer; // Self-reference to avoid NPE
        lenient().when(mockNdrBuffer.derive(anyInt())).thenReturn(mockDeferredNdrBuffer);
        lenient().when(mockDeferredNdrBuffer.derive(anyInt())).thenReturn(mockDeferredNdrBuffer);

        // Set up lenient stubs for common operations to avoid unnecessary stubbing exceptions
        lenient().when(mockNdrBuffer.getIndex()).thenReturn(0);
        lenient().when(mockDeferredNdrBuffer.getIndex()).thenReturn(0);
        // Mock the index field access
        mockDeferredNdrBuffer.index = 0;
    }

    @Test
    void testGetSyntax() {
        // Test the static getSyntax method
        assertEquals("12345778-1234-abcd-ef00-0123456789ab:0.0", lsarpc.getSyntax());
    }

    static class MockNdrBuffer extends NdrBuffer {
        private byte[] data;
        private int offset;

        public MockNdrBuffer(byte[] data) {
            super(data, 0);
            this.data = data;
            this.offset = 0;
        }

        @Override
        public int align(int a) {
            // Simulate alignment by advancing offset
            int remainder = offset % a;
            if (remainder != 0) {
                offset += (a - remainder);
            }
            return 0; // Return dummy value
        }

        @Override
        public void enc_ndr_long(int v) {
            // Simulate encoding a long
            offset += 4;
        }

        @Override
        public int dec_ndr_long() {
            // Simulate decoding a long
            offset += 4;
            return 0; // Return a dummy value
        }

        @Override
        public void enc_ndr_short(int v) {
            // Simulate encoding a short
            offset += 2;
        }

        @Override
        public int dec_ndr_short() {
            // Simulate decoding a short
            offset += 2;
            return 0; // Return a dummy value
        }

        @Override
        public void enc_ndr_small(int v) {
            // Simulate encoding a small
            offset += 1;
        }

        @Override
        public int dec_ndr_small() {
            // Simulate decoding a small
            offset += 1;
            return 0; // Return a dummy value
        }

        @Override
        public void enc_ndr_referent(Object obj, int type) {
            // Simulate encoding a referent
            offset += 4;
        }

        // Note: dec_ndr_long_and_advance() method does not exist in NdrBuffer
        public int dec_ndr_long_and_advance() {
            offset += 4;
            return 0;
        }

        // Note: dec_ndr_long_and_advance(int) method does not exist in NdrBuffer
        public int dec_ndr_long_and_advance(int count) {
            offset += 4 * count;
            return 0;
        }

        @Override
        public void advance(int bytes) {
            offset += bytes;
        }

        @Override
        public int getIndex() {
            return offset;
        }

        @Override
        public NdrBuffer derive(int offset) {
            return this; // For simplicity, return self
        }

        // Note: getDeferred() method does not exist in NdrBuffer
        public NdrBuffer getDeferred() {
            return this; // For simplicity, return self
        }

        @Override
        public void enc_ndr_string(String s) {
            // Simulate encoding a string
            offset += (s.length() * 2) + 4; // Length + null terminator + actual string
        }
    }

    // Test for LsarQosInfo
    @Test
    void testLsarQosInfoEncode() throws NdrException {
        lsarpc.LsarQosInfo qosInfo = new lsarpc.LsarQosInfo();
        qosInfo.length = 10;
        qosInfo.impersonation_level = 1;
        qosInfo.context_mode = 2;
        qosInfo.effective_only = 3;

        qosInfo.encode(mockNdrBuffer);

        // Verify encode calls
        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_long(qosInfo.length);
        verify(mockNdrBuffer).enc_ndr_short(qosInfo.impersonation_level);
        verify(mockNdrBuffer).enc_ndr_small(qosInfo.context_mode);
        verify(mockNdrBuffer).enc_ndr_small(qosInfo.effective_only);
    }

    @Test
    void testLsarQosInfoDecode() throws NdrException {
        lsarpc.LsarQosInfo qosInfo = new lsarpc.LsarQosInfo();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(10);
        when(mockNdrBuffer.dec_ndr_short()).thenReturn(1);
        when(mockNdrBuffer.dec_ndr_small()).thenReturn(2, 3);

        qosInfo.decode(mockNdrBuffer);

        // Verify decoded values
        assertEquals(10, qosInfo.length);
        assertEquals(1, qosInfo.impersonation_level);
        assertEquals(2, qosInfo.context_mode);
        assertEquals(3, qosInfo.effective_only);

        // Verify decode calls
        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer, times(1)).dec_ndr_long();
        verify(mockNdrBuffer, times(1)).dec_ndr_short();
        verify(mockNdrBuffer, times(2)).dec_ndr_small();
    }

    // Test for LsarObjectAttributes
    @Test
    void testLsarObjectAttributesEncode() throws NdrException {
        lsarpc.LsarObjectAttributes objAttr = new lsarpc.LsarObjectAttributes();
        objAttr.length = 100;
        objAttr.root_directory = mock(NdrSmall.class);
        objAttr.object_name = mock(rpc.unicode_string.class);
        objAttr.attributes = 1;
        objAttr.security_descriptor = 2;
        objAttr.security_quality_of_service = mock(lsarpc.LsarQosInfo.class);

        objAttr.encode(mockNdrBuffer);

        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_long(objAttr.length);
        verify(mockNdrBuffer).enc_ndr_referent(objAttr.root_directory, 1);
        verify(mockNdrBuffer).enc_ndr_referent(objAttr.object_name, 1);
        verify(mockNdrBuffer).enc_ndr_long(objAttr.attributes);
        verify(mockNdrBuffer).enc_ndr_long(objAttr.security_descriptor);
        verify(mockNdrBuffer).enc_ndr_referent(objAttr.security_quality_of_service, 1);

        // The actual implementation reassigns _dst = _dst.deferred inside encode(), so we can't verify the exact buffer
        verify(objAttr.root_directory).encode(any(NdrBuffer.class));
        verify(objAttr.object_name).encode(any(NdrBuffer.class));
        verify(objAttr.security_quality_of_service).encode(any(NdrBuffer.class));
    }

    @Test
    void testLsarObjectAttributesEncodeNullReferents() throws NdrException {
        lsarpc.LsarObjectAttributes objAttr = new lsarpc.LsarObjectAttributes();
        objAttr.length = 100;
        objAttr.root_directory = null;
        objAttr.object_name = null;
        objAttr.attributes = 1;
        objAttr.security_descriptor = 2;
        objAttr.security_quality_of_service = null;

        objAttr.encode(mockNdrBuffer);

        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_long(objAttr.length);
        verify(mockNdrBuffer, times(3)).enc_ndr_referent(null, 1); // Called 3 times for null root_directory, object_name, and security_quality_of_service
        verify(mockNdrBuffer).enc_ndr_long(objAttr.attributes);
        verify(mockNdrBuffer).enc_ndr_long(objAttr.security_descriptor);

        // Note: NdrBuffer does not have encode method
    }

    @Test
    void testLsarObjectAttributesDecode() throws NdrException {
        lsarpc.LsarObjectAttributes objAttr = new lsarpc.LsarObjectAttributes();
        objAttr.root_directory = mock(NdrSmall.class); // Pre-initialize for decode path
        objAttr.object_name = mock(rpc.unicode_string.class); // Pre-initialize for decode path
        objAttr.security_quality_of_service = mock(lsarpc.LsarQosInfo.class); // Pre-initialize for decode path

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(100, 1, 2, 3, 4, 5); // length, _root_directoryp, _object_namep, attributes, security_descriptor, _security_quality_of_servicep

        objAttr.decode(mockNdrBuffer);

        assertEquals(100, objAttr.length);
        assertEquals(3, objAttr.attributes);
        assertEquals(4, objAttr.security_descriptor);

        verify(objAttr.root_directory).decode(mockDeferredNdrBuffer);
        verify(objAttr.object_name).decode(mockDeferredNdrBuffer);
        verify(objAttr.security_quality_of_service).decode(mockDeferredNdrBuffer);
    }

    @Test
    void testLsarObjectAttributesDecodeNullReferents() throws NdrException {
        lsarpc.LsarObjectAttributes objAttr = new lsarpc.LsarObjectAttributes();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(100, 0, 0, 3, 4, 0); // length, _root_directoryp (null), _object_namep (null), attributes, security_descriptor, _security_quality_of_servicep (null)

        objAttr.decode(mockNdrBuffer);

        assertEquals(100, objAttr.length);
        assertNull(objAttr.root_directory); // null because _root_directoryp was 0
        assertNull(objAttr.object_name); // Should be null when _object_namep is 0
        assertEquals(3, objAttr.attributes);
        assertEquals(4, objAttr.security_descriptor);
        assertNull(objAttr.security_quality_of_service); // Should be null when _security_quality_of_servicep is 0

        // Note: NdrBuffer does not have decode method
    }

    // Test for LsarDomainInfo
    @Test
    void testLsarDomainInfoEncode() throws NdrException {
        lsarpc.LsarDomainInfo domainInfo = new lsarpc.LsarDomainInfo();
        domainInfo.name = new rpc.unicode_string(); // Use real object, not mock
        domainInfo.name.length = 10;
        domainInfo.name.maximum_length = 20;
        domainInfo.name.buffer = new short[10];
        domainInfo.sid = mock(rpc.sid_t.class);

        // The index property is already set in setUp()

        domainInfo.encode(mockNdrBuffer);

        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_short(domainInfo.name.length);
        verify(mockNdrBuffer).enc_ndr_short(domainInfo.name.maximum_length);
        verify(mockNdrBuffer).enc_ndr_referent(domainInfo.name.buffer, 1);
        verify(mockNdrBuffer).enc_ndr_referent(domainInfo.sid, 1);

        verify(mockDeferredNdrBuffer).enc_ndr_long(domainInfo.name.maximum_length / 2);
        verify(mockDeferredNdrBuffer).enc_ndr_long(0);
        verify(mockDeferredNdrBuffer).enc_ndr_long(domainInfo.name.length / 2);
        verify(mockDeferredNdrBuffer).advance(2 * (domainInfo.name.length / 2));
        verify(mockDeferredNdrBuffer).derive(anyInt());
        verify(mockDeferredNdrBuffer, times(5)).enc_ndr_short(0); // Writing 5 shorts with value 0
        verify(domainInfo.sid).encode(mockDeferredNdrBuffer); // Should be called with deferred buffer
    }

    @Test
    void testLsarDomainInfoEncodeNullReferents() throws NdrException {
        lsarpc.LsarDomainInfo domainInfo = new lsarpc.LsarDomainInfo();
        domainInfo.name = new rpc.unicode_string(); // Use real object
        domainInfo.name.buffer = null; // Null buffer
        domainInfo.sid = null; // Null SID

        domainInfo.encode(mockNdrBuffer);

        verify(mockNdrBuffer, times(2)).enc_ndr_referent(null, 1); // name.buffer and sid
        verify(mockDeferredNdrBuffer, never()).enc_ndr_long(anyInt());
        verify(mockDeferredNdrBuffer, never()).enc_ndr_short(anyShort());
        // Note: NdrBuffer does not have encode method
    }

    @Test
    void testLsarDomainInfoDecode() throws NdrException {
        lsarpc.LsarDomainInfo domainInfo = new lsarpc.LsarDomainInfo();
        domainInfo.name = new rpc.unicode_string(); // Initialize name
        domainInfo.sid = mock(rpc.sid_t.class); // Initialize sid

        when(mockNdrBuffer.dec_ndr_short()).thenReturn(10, 20);
        when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 2);
        // The implementation uses maximum_length/2 for _name_buffers, not length
        when(mockDeferredNdrBuffer.dec_ndr_long()).thenReturn(10, 0, 5); // _name_buffers (max_length/2 = 20/2 = 10), 0, _name_bufferl (5)
        when(mockDeferredNdrBuffer.dec_ndr_short()).thenReturn((int) (short) 'a', (int) (short) 'b', (int) (short) 'c', (int) (short) 'd',
                (int) (short) 'e');

        domainInfo.decode(mockNdrBuffer);

        assertEquals(10, domainInfo.name.length);
        assertEquals(20, domainInfo.name.maximum_length);
        assertNotNull(domainInfo.name.buffer);
        assertEquals(10, domainInfo.name.buffer.length); // Should be _name_buffers which is maximum_length/2
        assertEquals('a', domainInfo.name.buffer[0]);
        verify(domainInfo.sid).decode(mockDeferredNdrBuffer);
    }

    @Test
    void testLsarDomainInfoDecodeNullReferents() throws NdrException {
        lsarpc.LsarDomainInfo domainInfo = new lsarpc.LsarDomainInfo();
        domainInfo.name = new rpc.unicode_string();

        when(mockNdrBuffer.dec_ndr_short()).thenReturn((int) (short) 0, (int) (short) 0);
        when(mockNdrBuffer.dec_ndr_long()).thenReturn(0, 0); // _name_bufferp (null), _sidp (null)

        domainInfo.decode(mockNdrBuffer);

        assertEquals(0, domainInfo.name.length);
        assertEquals(0, domainInfo.name.maximum_length);
        assertNull(domainInfo.name.buffer);
        assertNull(domainInfo.sid);

        verify(mockDeferredNdrBuffer, never()).dec_ndr_long();
        verify(mockDeferredNdrBuffer, never()).dec_ndr_short();
        // Note: NdrBuffer does not have decode method
    }

    @Test
    void testLsarDomainInfoDecodeInvalidConformance() {
        lsarpc.LsarDomainInfo domainInfo = new lsarpc.LsarDomainInfo();
        domainInfo.name = new rpc.unicode_string();

        when(mockNdrBuffer.dec_ndr_short()).thenReturn((int) (int) (short) 10, (int) (int) (short) 20);
        when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 2);
        when(mockDeferredNdrBuffer.dec_ndr_long()).thenReturn(-1, 0, 5); // Invalid _name_buffers

        assertThrows(NdrException.class, () -> domainInfo.decode(mockNdrBuffer));
    }

    // Test for LsarDnsDomainInfo
    @Test
    void testLsarDnsDomainInfoEncode() throws NdrException {
        lsarpc.LsarDnsDomainInfo dnsDomainInfo = new lsarpc.LsarDnsDomainInfo();
        dnsDomainInfo.name = new rpc.unicode_string();
        dnsDomainInfo.name.length = 10;
        dnsDomainInfo.name.maximum_length = 20;
        dnsDomainInfo.name.buffer = new short[5];

        dnsDomainInfo.dns_domain = new rpc.unicode_string();
        dnsDomainInfo.dns_domain.length = 12;
        dnsDomainInfo.dns_domain.maximum_length = 24;
        dnsDomainInfo.dns_domain.buffer = new short[6];

        dnsDomainInfo.dns_forest = new rpc.unicode_string();
        dnsDomainInfo.dns_forest.length = 14;
        dnsDomainInfo.dns_forest.maximum_length = 28;
        dnsDomainInfo.dns_forest.buffer = new short[7];

        dnsDomainInfo.domain_guid = new rpc.uuid_t();
        dnsDomainInfo.domain_guid.time_low = 1;
        dnsDomainInfo.domain_guid.time_mid = 2;
        dnsDomainInfo.domain_guid.time_hi_and_version = 3;
        dnsDomainInfo.domain_guid.clock_seq_hi_and_reserved = 4;
        dnsDomainInfo.domain_guid.clock_seq_low = 5;
        dnsDomainInfo.domain_guid.node = new byte[6];

        dnsDomainInfo.sid = mock(rpc.sid_t.class);

        dnsDomainInfo.encode(mockNdrBuffer);

        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_short(dnsDomainInfo.name.length);
        verify(mockNdrBuffer).enc_ndr_short(dnsDomainInfo.name.maximum_length);
        verify(mockNdrBuffer).enc_ndr_referent(dnsDomainInfo.name.buffer, 1);

        verify(mockNdrBuffer).enc_ndr_short(dnsDomainInfo.dns_domain.length);
        verify(mockNdrBuffer).enc_ndr_short(dnsDomainInfo.dns_domain.maximum_length);
        verify(mockNdrBuffer).enc_ndr_referent(dnsDomainInfo.dns_domain.buffer, 1);

        verify(mockNdrBuffer).enc_ndr_short(dnsDomainInfo.dns_forest.length);
        verify(mockNdrBuffer).enc_ndr_short(dnsDomainInfo.dns_forest.maximum_length);
        verify(mockNdrBuffer).enc_ndr_referent(dnsDomainInfo.dns_forest.buffer, 1);

        verify(mockNdrBuffer).enc_ndr_long(dnsDomainInfo.domain_guid.time_low);
        verify(mockNdrBuffer).enc_ndr_short(dnsDomainInfo.domain_guid.time_mid);
        verify(mockNdrBuffer).enc_ndr_short(dnsDomainInfo.domain_guid.time_hi_and_version);
        verify(mockNdrBuffer).enc_ndr_small(dnsDomainInfo.domain_guid.clock_seq_hi_and_reserved);
        verify(mockNdrBuffer).enc_ndr_small(dnsDomainInfo.domain_guid.clock_seq_low);
        verify(mockNdrBuffer).advance(1 * 6); // domain_guid.node

        verify(mockNdrBuffer).enc_ndr_referent(dnsDomainInfo.sid, 1);

        verify(mockDeferredNdrBuffer, times(9)).enc_ndr_long(anyInt()); // 3 enc_ndr_long for each of 3 unicode strings
        verify(mockDeferredNdrBuffer, times(3)).enc_ndr_long(0);
        verify(mockDeferredNdrBuffer, times(3)).advance(anyInt());
        verify(mockDeferredNdrBuffer, times(4)).derive(anyInt()); // 3 for strings + 1 for guid
        verify(mockDeferredNdrBuffer, times(18)).enc_ndr_short(0); // 5+6+7 shorts with value 0
        verify(mockDeferredNdrBuffer, times(6)).enc_ndr_small(0); // For domain_guid.node - all 0
        verify(dnsDomainInfo.sid).encode(any(NdrBuffer.class)); // Buffer reassignment happens inside encode
    }

    @Test
    void testLsarDnsDomainInfoEncodeNullReferents() throws NdrException {
        lsarpc.LsarDnsDomainInfo dnsDomainInfo = new lsarpc.LsarDnsDomainInfo();
        dnsDomainInfo.name = new rpc.unicode_string();
        dnsDomainInfo.name.buffer = null;
        dnsDomainInfo.dns_domain = new rpc.unicode_string();
        dnsDomainInfo.dns_domain.buffer = null;
        dnsDomainInfo.dns_forest = new rpc.unicode_string();
        dnsDomainInfo.dns_forest.buffer = null;
        dnsDomainInfo.domain_guid = new rpc.uuid_t();
        dnsDomainInfo.domain_guid.node = new byte[6]; // Cannot be null as encode() accesses it
        dnsDomainInfo.sid = null;

        dnsDomainInfo.encode(mockNdrBuffer);

        // Verify all fields are encoded in order
        // enc_ndr_short(0) is called 8 times total in the specific order
        verify(mockNdrBuffer, times(8)).enc_ndr_short(0); // 2 for name, 2 for dns_domain, 2 for dns_forest, 2 for guid
        verify(mockNdrBuffer, times(4)).enc_ndr_referent(null, 1); // name.buffer, dns_domain.buffer, dns_forest.buffer, sid

        verify(mockNdrBuffer).enc_ndr_long(dnsDomainInfo.domain_guid.time_low);
        // Note: enc_ndr_short(0) for guid fields is already verified above with times(8)
        verify(mockNdrBuffer, times(2)).enc_ndr_small(0); // clock_seq_hi_and_reserved and clock_seq_low are both 0
        verify(mockNdrBuffer).advance(1 * 6); // domain_guid.node
        verify(mockDeferredNdrBuffer, times(6)).enc_ndr_small(0); // node bytes all 0

        // Note: enc_ndr_referent(null, 1) is already verified above with times(4)
    }

    @Test
    void testLsarDnsDomainInfoDecode() throws NdrException {
        lsarpc.LsarDnsDomainInfo dnsDomainInfo = new lsarpc.LsarDnsDomainInfo();
        dnsDomainInfo.name = new rpc.unicode_string();
        dnsDomainInfo.dns_domain = new rpc.unicode_string();
        dnsDomainInfo.dns_forest = new rpc.unicode_string();
        dnsDomainInfo.domain_guid = new rpc.uuid_t();
        dnsDomainInfo.sid = mock(rpc.sid_t.class);

        when(mockNdrBuffer.dec_ndr_short()).thenReturn(10, 20, 12, 24, 14, 28);
        when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, // _name_bufferp
                2, // _dns_domain_bufferp
                3, // _dns_forest_bufferp
                100, // domain_guid.time_low
                4 // _sidp
        );
        when(mockNdrBuffer.dec_ndr_small()).thenReturn(4, 5);
        when(mockDeferredNdrBuffer.dec_ndr_long()).thenReturn(5, 0, 5, // name buffer: buffers, 0, bufferl
                6, 0, 6, // dns_domain buffer: buffers, 0, bufferl
                7, 0, 7 // dns_forest buffer: buffers, 0, bufferl
        );
        when(mockDeferredNdrBuffer.dec_ndr_short()).thenReturn((int) (short) 'a', (int) (int) (short) 'b', (int) (int) (short) 'c',
                (int) (int) (short) 'd', (int) (int) (short) 'e', (int) (short) 'f', (int) (short) 'g', (int) (short) 'h',
                (int) (short) 'i', (int) (short) 'j', (int) (short) 'k', (int) (short) 'l', (int) (short) 'm', (int) (short) 'n',
                (int) (short) 'o', (int) (short) 'p', (int) (short) 'q', (int) (short) 'r');
        when(mockDeferredNdrBuffer.dec_ndr_small()).thenReturn(1, 2, 3, 4, 5, 6);

        dnsDomainInfo.decode(mockNdrBuffer);

        assertEquals(10, dnsDomainInfo.name.length);
        assertEquals(20, dnsDomainInfo.name.maximum_length);
        assertNotNull(dnsDomainInfo.name.buffer);
        assertEquals(5, dnsDomainInfo.name.buffer.length);

        assertEquals(12, dnsDomainInfo.dns_domain.length);
        assertEquals(24, dnsDomainInfo.dns_domain.maximum_length);
        assertNotNull(dnsDomainInfo.dns_domain.buffer);
        assertEquals(6, dnsDomainInfo.dns_domain.buffer.length);

        assertEquals(14, dnsDomainInfo.dns_forest.length);
        assertEquals(28, dnsDomainInfo.dns_forest.maximum_length);
        assertNotNull(dnsDomainInfo.dns_forest.buffer);
        assertEquals(7, dnsDomainInfo.dns_forest.buffer.length);

        assertEquals(100, dnsDomainInfo.domain_guid.time_low);
        assertNotNull(dnsDomainInfo.domain_guid.node);
        assertEquals(6, dnsDomainInfo.domain_guid.node.length);

        verify(dnsDomainInfo.sid).decode(mockDeferredNdrBuffer);
    }

    @Test
    void testLsarDnsDomainInfoDecodeNullReferents() throws NdrException {
        lsarpc.LsarDnsDomainInfo dnsDomainInfo = new lsarpc.LsarDnsDomainInfo();
        dnsDomainInfo.name = new rpc.unicode_string();
        dnsDomainInfo.dns_domain = new rpc.unicode_string();
        dnsDomainInfo.dns_forest = new rpc.unicode_string();
        dnsDomainInfo.domain_guid = new rpc.uuid_t();

        when(mockNdrBuffer.dec_ndr_short()).thenReturn((int) (int) (short) 0, (int) (int) (short) 0, // name
                (int) (int) (short) 0, (int) (int) (short) 0, // dns_domain
                (int) (int) (short) 0, (int) (int) (short) 0 // dns_forest
        );
        when(mockNdrBuffer.dec_ndr_long()).thenReturn(0, // _name_bufferp
                0, // _dns_domain_bufferp
                0, // _dns_forest_bufferp
                100, // domain_guid.time_low
                0 // _sidp
        );
        when(mockNdrBuffer.dec_ndr_small()).thenReturn(4, 5);

        dnsDomainInfo.decode(mockNdrBuffer);

        assertNull(dnsDomainInfo.name.buffer);
        assertNull(dnsDomainInfo.dns_domain.buffer);
        assertNull(dnsDomainInfo.dns_forest.buffer);
        assertNull(dnsDomainInfo.sid);
        assertNotNull(dnsDomainInfo.domain_guid.node); // Should be initialized even if null in encode
        assertEquals(6, dnsDomainInfo.domain_guid.node.length);
    }

    @Test
    void testLsarDnsDomainInfoDecodeInvalidConformance() {
        lsarpc.LsarDnsDomainInfo dnsDomainInfo = new lsarpc.LsarDnsDomainInfo();
        dnsDomainInfo.name = new rpc.unicode_string();

        when(mockNdrBuffer.dec_ndr_short()).thenReturn((int) (short) 10, (int) (short) 20, (int) (short) 0, (int) (short) 0,
                (int) (short) 0, (int) (short) 0);
        when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 0, 0, 0, 0);
        when(mockDeferredNdrBuffer.dec_ndr_long()).thenReturn(-1, 0, 5); // Invalid _name_buffers

        assertThrows(NdrException.class, () -> dnsDomainInfo.decode(mockNdrBuffer));
    }

    // Test for LsarSidPtr
    @Test
    void testLsarSidPtrEncode() throws NdrException {
        lsarpc.LsarSidPtr sidPtr = new lsarpc.LsarSidPtr();
        sidPtr.sid = mock(rpc.sid_t.class);

        sidPtr.encode(mockNdrBuffer);

        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_referent(sidPtr.sid, 1);
        verify(sidPtr.sid).encode(any(NdrBuffer.class)); // Buffer reassignment happens inside encode
    }

    @Test
    void testLsarSidPtrEncodeNullSid() throws NdrException {
        lsarpc.LsarSidPtr sidPtr = new lsarpc.LsarSidPtr();
        sidPtr.sid = null;

        sidPtr.encode(mockNdrBuffer);

        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_referent(null, 1);
        // Note: NdrBuffer does not have encode method
    }

    @Test
    void testLsarSidPtrDecode() throws NdrException {
        lsarpc.LsarSidPtr sidPtr = new lsarpc.LsarSidPtr();
        sidPtr.sid = mock(rpc.sid_t.class); // Pre-initialize for decode path

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(1); // _sidp

        sidPtr.decode(mockNdrBuffer);

        assertNotNull(sidPtr.sid);
        verify(sidPtr.sid).decode(mockDeferredNdrBuffer);
    }

    @Test
    void testLsarSidPtrDecodeNullSid() throws NdrException {
        lsarpc.LsarSidPtr sidPtr = new lsarpc.LsarSidPtr();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(0); // _sidp (null)

        sidPtr.decode(mockNdrBuffer);

        assertNull(sidPtr.sid); // Not initialized when _sidp is 0
        // Note: NdrBuffer does not have decode method
    }

    // Test for LsarSidArray
    @Test
    void testLsarSidArrayEncode() throws NdrException {
        lsarpc.LsarSidArray sidArray = new lsarpc.LsarSidArray();
        sidArray.num_sids = 2;
        sidArray.sids = new lsarpc.LsarSidPtr[2];
        sidArray.sids[0] = mock(lsarpc.LsarSidPtr.class);
        sidArray.sids[1] = mock(lsarpc.LsarSidPtr.class);

        sidArray.encode(mockNdrBuffer);

        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_long(sidArray.num_sids);
        verify(mockNdrBuffer).enc_ndr_referent(sidArray.sids, 1);

        verify(mockDeferredNdrBuffer).enc_ndr_long(sidArray.num_sids);
        verify(mockDeferredNdrBuffer).advance(4 * sidArray.num_sids);
        verify(sidArray.sids[0]).encode(any(NdrBuffer.class)); // Buffer reassignment happens inside encode
        verify(sidArray.sids[1]).encode(any(NdrBuffer.class)); // Buffer reassignment happens inside encode
    }

    @Test
    void testLsarSidArrayEncodeNullSids() throws NdrException {
        lsarpc.LsarSidArray sidArray = new lsarpc.LsarSidArray();
        sidArray.num_sids = 0;
        sidArray.sids = null;

        sidArray.encode(mockNdrBuffer);

        verify(mockNdrBuffer).enc_ndr_referent(null, 1);
        verify(mockDeferredNdrBuffer, never()).enc_ndr_long(anyInt());
        verify(mockDeferredNdrBuffer, never()).advance(anyInt());
        // Note: NdrBuffer does not have encode method
    }

    @Test
    void testLsarSidArrayDecode() throws NdrException {
        lsarpc.LsarSidArray sidArray = new lsarpc.LsarSidArray();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(2, 1); // num_sids, _sidsp
        when(mockDeferredNdrBuffer.dec_ndr_long()).thenReturn(2); // _sidss

        sidArray.decode(mockNdrBuffer);

        assertEquals(2, sidArray.num_sids);
        assertNotNull(sidArray.sids);
        assertEquals(2, sidArray.sids.length);
        assertNotNull(sidArray.sids[0]);
        assertNotNull(sidArray.sids[1]);
        // Cannot verify decode on non-mock objects - they are created by decode
        // Just verify they were created
        assertNotNull(sidArray.sids[0]);
        assertNotNull(sidArray.sids[1]);
    }

    @Test
    void testLsarSidArrayDecodeNullSids() throws NdrException {
        lsarpc.LsarSidArray sidArray = new lsarpc.LsarSidArray();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(0, 0); // num_sids, _sidsp (null)

        sidArray.decode(mockNdrBuffer);

        assertEquals(0, sidArray.num_sids);
        assertNull(sidArray.sids);

        verify(mockDeferredNdrBuffer, never()).dec_ndr_long();
        verify(mockDeferredNdrBuffer, never()).advance(anyInt());
        // Note: NdrBuffer does not have decode method
    }

    @Test
    void testLsarSidArrayDecodeInvalidConformance() {
        lsarpc.LsarSidArray sidArray = new lsarpc.LsarSidArray();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(2, 1);
        when(mockDeferredNdrBuffer.dec_ndr_long()).thenReturn(-1); // Invalid _sidss

        assertThrows(NdrException.class, () -> sidArray.decode(mockNdrBuffer));
    }

    // Test for LsarTranslatedSid
    @Test
    void testLsarTranslatedSidEncode() throws NdrException {
        lsarpc.LsarTranslatedSid translatedSid = new lsarpc.LsarTranslatedSid();
        translatedSid.sid_type = 1;
        translatedSid.rid = 2;
        translatedSid.sid_index = 3;

        translatedSid.encode(mockNdrBuffer);

        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_short(translatedSid.sid_type);
        verify(mockNdrBuffer).enc_ndr_long(translatedSid.rid);
        verify(mockNdrBuffer).enc_ndr_long(translatedSid.sid_index);
    }

    @Test
    void testLsarTranslatedSidDecode() throws NdrException {
        lsarpc.LsarTranslatedSid translatedSid = new lsarpc.LsarTranslatedSid();

        when(mockNdrBuffer.dec_ndr_short()).thenReturn(1);
        when(mockNdrBuffer.dec_ndr_long()).thenReturn(2, 3);

        translatedSid.decode(mockNdrBuffer);

        assertEquals(1, translatedSid.sid_type);
        assertEquals(2, translatedSid.rid);
        assertEquals(3, translatedSid.sid_index);

        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer, times(1)).dec_ndr_short();
        verify(mockNdrBuffer, times(2)).dec_ndr_long();
    }

    // Test for LsarTransSidArray
    @Test
    void testLsarTransSidArrayEncode() throws NdrException {
        lsarpc.LsarTransSidArray transSidArray = new lsarpc.LsarTransSidArray();
        transSidArray.count = 2;
        transSidArray.sids = new lsarpc.LsarTranslatedSid[2];
        transSidArray.sids[0] = mock(lsarpc.LsarTranslatedSid.class);
        transSidArray.sids[1] = mock(lsarpc.LsarTranslatedSid.class);

        transSidArray.encode(mockNdrBuffer);

        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_long(transSidArray.count);
        verify(mockNdrBuffer).enc_ndr_referent(transSidArray.sids, 1);

        verify(mockDeferredNdrBuffer).enc_ndr_long(transSidArray.count);
        verify(mockDeferredNdrBuffer).advance(12 * transSidArray.count);
        verify(transSidArray.sids[0]).encode(any(NdrBuffer.class)); // Buffer reassignment happens inside encode
        verify(transSidArray.sids[1]).encode(any(NdrBuffer.class)); // Buffer reassignment happens inside encode
    }

    @Test
    void testLsarTransSidArrayEncodeNullSids() throws NdrException {
        lsarpc.LsarTransSidArray transSidArray = new lsarpc.LsarTransSidArray();
        transSidArray.count = 0;
        transSidArray.sids = null;

        transSidArray.encode(mockNdrBuffer);

        verify(mockNdrBuffer).enc_ndr_referent(null, 1);
        verify(mockDeferredNdrBuffer, never()).enc_ndr_long(anyInt());
        verify(mockDeferredNdrBuffer, never()).advance(anyInt());
        // Note: NdrBuffer does not have encode method
    }

    @Test
    void testLsarTransSidArrayDecode() throws NdrException {
        lsarpc.LsarTransSidArray transSidArray = new lsarpc.LsarTransSidArray();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(2, 1); // count, _sidsp
        when(mockDeferredNdrBuffer.dec_ndr_long()).thenReturn(2); // _sidss

        transSidArray.decode(mockNdrBuffer);

        assertEquals(2, transSidArray.count);
        assertNotNull(transSidArray.sids);
        assertEquals(2, transSidArray.sids.length);
        assertNotNull(transSidArray.sids[0]);
        assertNotNull(transSidArray.sids[1]);
        // Cannot verify decode on non-mock objects - they are created by decode
        // Just verify they were created
        assertNotNull(transSidArray.sids[0]);
        assertNotNull(transSidArray.sids[1]);
    }

    @Test
    void testLsarTransSidArrayDecodeNullSids() throws NdrException {
        lsarpc.LsarTransSidArray transSidArray = new lsarpc.LsarTransSidArray();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(0, 0); // count, _sidsp (null)

        transSidArray.decode(mockNdrBuffer);

        assertEquals(0, transSidArray.count);
        assertNull(transSidArray.sids);

        verify(mockDeferredNdrBuffer, never()).dec_ndr_long();
        verify(mockDeferredNdrBuffer, never()).advance(anyInt());
        // Note: NdrBuffer does not have decode method
    }

    @Test
    void testLsarTransSidArrayDecodeInvalidConformance() {
        lsarpc.LsarTransSidArray transSidArray = new lsarpc.LsarTransSidArray();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(2, 1);
        when(mockDeferredNdrBuffer.dec_ndr_long()).thenReturn(-1); // Invalid _sidss

        assertThrows(NdrException.class, () -> transSidArray.decode(mockNdrBuffer));
    }

    // Test for LsarTrustInformation
    @Test
    void testLsarTrustInformationEncode() throws NdrException {
        lsarpc.LsarTrustInformation trustInfo = new lsarpc.LsarTrustInformation();
        trustInfo.name = new rpc.unicode_string(); // Use real object
        trustInfo.name.length = 10;
        trustInfo.name.maximum_length = 20;
        trustInfo.name.buffer = new short[10]; // Should match maximum_length/2
        trustInfo.sid = mock(rpc.sid_t.class);

        trustInfo.encode(mockNdrBuffer);

        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_short(trustInfo.name.length);
        verify(mockNdrBuffer).enc_ndr_short(trustInfo.name.maximum_length);
        verify(mockNdrBuffer).enc_ndr_referent(trustInfo.name.buffer, 1);
        verify(mockNdrBuffer).enc_ndr_referent(trustInfo.sid, 1);

        verify(mockDeferredNdrBuffer).enc_ndr_long(trustInfo.name.maximum_length / 2);
        verify(mockDeferredNdrBuffer).enc_ndr_long(0);
        verify(mockDeferredNdrBuffer).enc_ndr_long(trustInfo.name.length / 2);
        verify(mockDeferredNdrBuffer).advance(2 * (trustInfo.name.length / 2));
        // Verify the derive call
        verify(mockDeferredNdrBuffer).derive(anyInt());
        verify(mockDeferredNdrBuffer, times(5)).enc_ndr_short(0); // Writing 5 shorts with value 0
        verify(trustInfo.sid).encode(mockDeferredNdrBuffer); // Should be called with deferred buffer
    }

    @Test
    void testLsarTrustInformationEncodeNullReferents() throws NdrException {
        lsarpc.LsarTrustInformation trustInfo = new lsarpc.LsarTrustInformation();
        trustInfo.name = new rpc.unicode_string(); // Use real object
        trustInfo.name.buffer = null;
        trustInfo.sid = null;

        trustInfo.encode(mockNdrBuffer);

        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer, times(2)).enc_ndr_short(0); // length and maximum_length are both 0
        verify(mockNdrBuffer, times(2)).enc_ndr_referent(null, 1); // Called twice for name.buffer and sid
        verify(mockDeferredNdrBuffer, never()).enc_ndr_long(anyInt());
        verify(mockDeferredNdrBuffer, never()).enc_ndr_short(anyShort());
        // Note: NdrBuffer does not have encode method
    }

    @Test
    void testLsarTrustInformationDecode() throws NdrException {
        lsarpc.LsarTrustInformation trustInfo = new lsarpc.LsarTrustInformation();
        trustInfo.name = new rpc.unicode_string();
        trustInfo.sid = mock(rpc.sid_t.class);

        when(mockNdrBuffer.dec_ndr_short()).thenReturn(10, 20);
        when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 1); // _name_bufferp, _sidp
        when(mockDeferredNdrBuffer.dec_ndr_long()).thenReturn(10, 0, 5); // name buffer: buffers, 0, bufferl
        when(mockDeferredNdrBuffer.dec_ndr_short()).thenReturn((int) (short) 'a', (int) (short) 'b', (int) (short) 'c', (int) (short) 'd',
                (int) (short) 'e');

        trustInfo.decode(mockNdrBuffer);

        assertEquals(10, trustInfo.name.length);
        assertEquals(20, trustInfo.name.maximum_length);
        assertNotNull(trustInfo.name.buffer);
        assertEquals(10, trustInfo.name.buffer.length); // Should be _name_buffers which is maximum_length/2
        verify(trustInfo.sid).decode(mockDeferredNdrBuffer);
    }

    @Test
    void testLsarTrustInformationDecodeNullReferents() throws NdrException {
        lsarpc.LsarTrustInformation trustInfo = new lsarpc.LsarTrustInformation();
        trustInfo.name = new rpc.unicode_string();

        when(mockNdrBuffer.dec_ndr_short()).thenReturn((int) (short) 0, (int) (short) 0);
        when(mockNdrBuffer.dec_ndr_long()).thenReturn(0, 0);

        trustInfo.decode(mockNdrBuffer);

        assertNull(trustInfo.name.buffer);
        assertNull(trustInfo.sid);

        verify(mockDeferredNdrBuffer, never()).dec_ndr_long();
        verify(mockDeferredNdrBuffer, never()).dec_ndr_short();
        // Note: NdrBuffer does not have decode method
    }

    @Test
    void testLsarTrustInformationDecodeInvalidConformance() {
        lsarpc.LsarTrustInformation trustInfo = new lsarpc.LsarTrustInformation();
        trustInfo.name = new rpc.unicode_string();

        when(mockNdrBuffer.dec_ndr_short()).thenReturn((int) (short) 10, (int) (short) 20);
        when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 2);
        when(mockDeferredNdrBuffer.dec_ndr_long()).thenReturn(-1, 0, 5);

        assertThrows(NdrException.class, () -> trustInfo.decode(mockNdrBuffer));
    }

    // Test for LsarRefDomainList
    @Test
    void testLsarRefDomainListEncode() throws NdrException {
        lsarpc.LsarRefDomainList refDomainList = new lsarpc.LsarRefDomainList();
        refDomainList.count = 2;
        refDomainList.domains = new lsarpc.LsarTrustInformation[2];
        refDomainList.domains[0] = mock(lsarpc.LsarTrustInformation.class);
        refDomainList.domains[1] = mock(lsarpc.LsarTrustInformation.class);
        refDomainList.max_count = 5;

        refDomainList.encode(mockNdrBuffer);

        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_long(refDomainList.count);
        verify(mockNdrBuffer).enc_ndr_referent(refDomainList.domains, 1);
        verify(mockNdrBuffer).enc_ndr_long(refDomainList.max_count);

        verify(mockDeferredNdrBuffer).enc_ndr_long(refDomainList.count);
        verify(mockDeferredNdrBuffer).advance(12 * refDomainList.count);
        verify(refDomainList.domains[0]).encode(any(NdrBuffer.class)); // Buffer reassignment happens inside encode
        verify(refDomainList.domains[1]).encode(any(NdrBuffer.class)); // Buffer reassignment happens inside encode
    }

    @Test
    void testLsarRefDomainListEncodeNullDomains() throws NdrException {
        lsarpc.LsarRefDomainList refDomainList = new lsarpc.LsarRefDomainList();
        refDomainList.count = 0;
        refDomainList.domains = null;
        refDomainList.max_count = 0;

        refDomainList.encode(mockNdrBuffer);

        verify(mockNdrBuffer).enc_ndr_referent(null, 1);
        verify(mockDeferredNdrBuffer, never()).enc_ndr_long(anyInt());
        verify(mockDeferredNdrBuffer, never()).advance(anyInt());
        // Note: NdrBuffer does not have encode method
    }

    @Test
    void testLsarRefDomainListDecode() throws NdrException {
        lsarpc.LsarRefDomainList refDomainList = new lsarpc.LsarRefDomainList();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(2, 1, 5); // count, _domainsp, max_count
        when(mockDeferredNdrBuffer.dec_ndr_long()).thenReturn(2); // _domainss

        refDomainList.decode(mockNdrBuffer);

        assertEquals(2, refDomainList.count);
        assertEquals(5, refDomainList.max_count);
        assertNotNull(refDomainList.domains);
        assertEquals(2, refDomainList.domains.length);
        assertNotNull(refDomainList.domains[0]);
        assertNotNull(refDomainList.domains[1]);
        // Cannot verify decode on non-mock objects - they are created by decode
        // Just verify they were created
        assertNotNull(refDomainList.domains[0]);
        assertNotNull(refDomainList.domains[1]);
    }

    @Test
    void testLsarRefDomainListDecodeNullDomains() throws NdrException {
        lsarpc.LsarRefDomainList refDomainList = new lsarpc.LsarRefDomainList();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(0, 0, 0); // count, _domainsp (null), max_count

        refDomainList.decode(mockNdrBuffer);

        assertEquals(0, refDomainList.count);
        assertEquals(0, refDomainList.max_count);
        assertNull(refDomainList.domains);

        verify(mockDeferredNdrBuffer, never()).dec_ndr_long();
        verify(mockDeferredNdrBuffer, never()).advance(anyInt());
        // Note: NdrBuffer does not have decode method
    }

    @Test
    void testLsarRefDomainListDecodeInvalidConformance() {
        lsarpc.LsarRefDomainList refDomainList = new lsarpc.LsarRefDomainList();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(2, 1, 5);
        when(mockDeferredNdrBuffer.dec_ndr_long()).thenReturn(-1); // Invalid _domainss

        assertThrows(NdrException.class, () -> refDomainList.decode(mockNdrBuffer));
    }

    // Test for LsarTranslatedName
    @Test
    void testLsarTranslatedNameEncode() throws NdrException {
        lsarpc.LsarTranslatedName translatedName = new lsarpc.LsarTranslatedName();
        translatedName.sid_type = 1;
        translatedName.name = new rpc.unicode_string(); // Use real object
        translatedName.name.length = 10;
        translatedName.name.maximum_length = 20;
        translatedName.name.buffer = new short[10]; // Should match maximum_length/2
        translatedName.sid_index = 3;

        translatedName.encode(mockNdrBuffer);

        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_short(translatedName.sid_type);
        verify(mockNdrBuffer).enc_ndr_short(translatedName.name.length);
        verify(mockNdrBuffer).enc_ndr_short(translatedName.name.maximum_length);
        verify(mockNdrBuffer).enc_ndr_referent(translatedName.name.buffer, 1);
        verify(mockNdrBuffer).enc_ndr_long(translatedName.sid_index);

        verify(mockDeferredNdrBuffer).enc_ndr_long(translatedName.name.maximum_length / 2);
        verify(mockDeferredNdrBuffer).enc_ndr_long(0);
        verify(mockDeferredNdrBuffer).enc_ndr_long(translatedName.name.length / 2);
        verify(mockDeferredNdrBuffer).advance(2 * (translatedName.name.length / 2));
        verify(mockDeferredNdrBuffer).derive(anyInt());
        verify(mockDeferredNdrBuffer, times(5)).enc_ndr_short(0); // Writing 5 shorts with value 0
    }

    @Test
    void testLsarTranslatedNameEncodeNullNameBuffer() throws NdrException {
        lsarpc.LsarTranslatedName translatedName = new lsarpc.LsarTranslatedName();
        translatedName.sid_type = 1;
        translatedName.name = new rpc.unicode_string(); // Use real object
        translatedName.name.buffer = null;
        translatedName.sid_index = 3;

        translatedName.encode(mockNdrBuffer);

        verify(mockNdrBuffer).enc_ndr_referent(null, 1);
        verify(mockDeferredNdrBuffer, never()).enc_ndr_long(anyInt());
        verify(mockDeferredNdrBuffer, never()).enc_ndr_short(anyShort());
    }

    @Test
    void testLsarTranslatedNameDecode() throws NdrException {
        lsarpc.LsarTranslatedName translatedName = new lsarpc.LsarTranslatedName();
        translatedName.name = new rpc.unicode_string();

        when(mockNdrBuffer.dec_ndr_short()).thenReturn(1, 10, 20);
        when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 3); // _name_bufferp, sid_index
        when(mockDeferredNdrBuffer.dec_ndr_long()).thenReturn(10, 0, 5); // name buffer: buffers, 0, bufferl
        when(mockDeferredNdrBuffer.dec_ndr_short()).thenReturn((int) (short) 'a', (int) (short) 'b', (int) (short) 'c', (int) (short) 'd',
                (int) (short) 'e');

        translatedName.decode(mockNdrBuffer);

        assertEquals(1, translatedName.sid_type);
        assertEquals(10, translatedName.name.length);
        assertEquals(20, translatedName.name.maximum_length);
        assertNotNull(translatedName.name.buffer);
        assertEquals(10, translatedName.name.buffer.length); // Should match _name_buffers which is maximum_length/2
        assertEquals(3, translatedName.sid_index);
    }

    @Test
    void testLsarTranslatedNameDecodeNullNameBuffer() throws NdrException {
        lsarpc.LsarTranslatedName translatedName = new lsarpc.LsarTranslatedName();
        translatedName.name = new rpc.unicode_string();

        when(mockNdrBuffer.dec_ndr_short()).thenReturn(1, 0, 0);
        when(mockNdrBuffer.dec_ndr_long()).thenReturn(0, 3); // _name_bufferp (null)

        translatedName.decode(mockNdrBuffer);

        assertEquals(1, translatedName.sid_type);
        assertEquals(0, translatedName.name.length);
        assertEquals(0, translatedName.name.maximum_length);
        assertNull(translatedName.name.buffer);
        assertEquals(3, translatedName.sid_index);

        verify(mockDeferredNdrBuffer, never()).dec_ndr_long();
        verify(mockDeferredNdrBuffer, never()).dec_ndr_short();
    }

    @Test
    void testLsarTranslatedNameDecodeInvalidConformance() {
        lsarpc.LsarTranslatedName translatedName = new lsarpc.LsarTranslatedName();
        translatedName.name = new rpc.unicode_string();

        when(mockNdrBuffer.dec_ndr_short()).thenReturn(1, 10, 20);
        when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 3);
        when(mockDeferredNdrBuffer.dec_ndr_long()).thenReturn(-1, 0, 5);

        assertThrows(NdrException.class, () -> translatedName.decode(mockNdrBuffer));
    }

    // Test for LsarTransNameArray
    @Test
    void testLsarTransNameArrayEncode() throws NdrException {
        lsarpc.LsarTransNameArray transNameArray = new lsarpc.LsarTransNameArray();
        transNameArray.count = 2;
        transNameArray.names = new lsarpc.LsarTranslatedName[2];
        transNameArray.names[0] = mock(lsarpc.LsarTranslatedName.class);
        transNameArray.names[1] = mock(lsarpc.LsarTranslatedName.class);

        transNameArray.encode(mockNdrBuffer);

        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_long(transNameArray.count);
        verify(mockNdrBuffer).enc_ndr_referent(transNameArray.names, 1);

        verify(mockDeferredNdrBuffer).enc_ndr_long(transNameArray.count);
        verify(mockDeferredNdrBuffer).advance(16 * transNameArray.count);
        verify(transNameArray.names[0]).encode(any(NdrBuffer.class)); // Buffer reassignment happens inside encode
        verify(transNameArray.names[1]).encode(any(NdrBuffer.class)); // Buffer reassignment happens inside encode
    }

    @Test
    void testLsarTransNameArrayEncodeNullNames() throws NdrException {
        lsarpc.LsarTransNameArray transNameArray = new lsarpc.LsarTransNameArray();
        transNameArray.count = 0;
        transNameArray.names = null;

        transNameArray.encode(mockNdrBuffer);

        verify(mockNdrBuffer).enc_ndr_referent(null, 1);
        verify(mockDeferredNdrBuffer, never()).enc_ndr_long(anyInt());
        verify(mockDeferredNdrBuffer, never()).advance(anyInt());
        // Note: NdrBuffer does not have encode method
    }

    @Test
    void testLsarTransNameArrayDecode() throws NdrException {
        lsarpc.LsarTransNameArray transNameArray = new lsarpc.LsarTransNameArray();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(2, 1); // count, _namesp
        when(mockDeferredNdrBuffer.dec_ndr_long()).thenReturn(2); // _namess

        transNameArray.decode(mockNdrBuffer);

        assertEquals(2, transNameArray.count);
        assertNotNull(transNameArray.names);
        assertEquals(2, transNameArray.names.length);
        assertNotNull(transNameArray.names[0]);
        assertNotNull(transNameArray.names[1]);
        // Cannot verify decode on non-mock objects - they are created by decode
        // Just verify they were created
        assertNotNull(transNameArray.names[0]);
        assertNotNull(transNameArray.names[1]);
    }

    @Test
    void testLsarTransNameArrayDecodeNullNames() throws NdrException {
        lsarpc.LsarTransNameArray transNameArray = new lsarpc.LsarTransNameArray();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(0, 0); // count, _namesp (null)

        transNameArray.decode(mockNdrBuffer);

        assertEquals(0, transNameArray.count);
        assertNull(transNameArray.names);

        verify(mockDeferredNdrBuffer, never()).dec_ndr_long();
        verify(mockDeferredNdrBuffer, never()).advance(anyInt());
        // Note: NdrBuffer does not have decode method
    }

    @Test
    void testLsarTransNameArrayDecodeInvalidConformance() {
        lsarpc.LsarTransNameArray transNameArray = new lsarpc.LsarTransNameArray();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(2, 1);
        when(mockDeferredNdrBuffer.dec_ndr_long()).thenReturn(-1); // Invalid _namess

        assertThrows(NdrException.class, () -> transNameArray.decode(mockNdrBuffer));
    }

    // Test for LsarClose
    @Test
    void testLsarCloseConstructorAndGetOpnum() {
        rpc.policy_handle mockHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarClose lsarClose = new lsarpc.LsarClose(mockHandle);

        assertEquals(mockHandle, lsarClose.handle);
        assertEquals(0x00, lsarClose.getOpnum());
    }

    @Test
    void testLsarCloseEncodeIn() throws NdrException {
        rpc.policy_handle mockHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarClose lsarClose = new lsarpc.LsarClose(mockHandle);

        lsarClose.encode_in(mockNdrBuffer);

        verify(mockHandle).encode(mockNdrBuffer);
    }

    @Test
    void testLsarCloseDecodeOut() throws NdrException {
        rpc.policy_handle mockHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarClose lsarClose = new lsarpc.LsarClose(mockHandle);

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(123); // retval

        lsarClose.decode_out(mockNdrBuffer);

        verify(mockHandle).decode(mockNdrBuffer);
        assertEquals(123, lsarClose.retval);
    }

    // Test for LsarQueryInformationPolicy
    @Test
    void testLsarQueryInformationPolicyConstructorAndGetOpnum() {
        rpc.policy_handle mockHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarQosInfo mockInfo = mock(lsarpc.LsarQosInfo.class);
        lsarpc.LsarQueryInformationPolicy queryInfoPolicy = new lsarpc.LsarQueryInformationPolicy(mockHandle, (short) 1, mockInfo);

        assertEquals(mockHandle, queryInfoPolicy.handle);
        assertEquals(1, queryInfoPolicy.level);
        assertEquals(mockInfo, queryInfoPolicy.info);
        assertEquals(0x07, queryInfoPolicy.getOpnum());
    }

    @Test
    void testLsarQueryInformationPolicyEncodeIn() throws NdrException {
        rpc.policy_handle mockHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarQosInfo mockInfo = mock(lsarpc.LsarQosInfo.class);
        lsarpc.LsarQueryInformationPolicy queryInfoPolicy = new lsarpc.LsarQueryInformationPolicy(mockHandle, (short) 1, mockInfo);

        queryInfoPolicy.encode_in(mockNdrBuffer);

        verify(mockHandle).encode(mockNdrBuffer);
        verify(mockNdrBuffer).enc_ndr_short((short) 1);
    }

    @Test
    void testLsarQueryInformationPolicyDecodeOut() throws NdrException {
        rpc.policy_handle mockHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarQosInfo mockInfo = mock(lsarpc.LsarQosInfo.class);
        lsarpc.LsarQueryInformationPolicy queryInfoPolicy = new lsarpc.LsarQueryInformationPolicy(mockHandle, (short) 1, mockInfo);

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 123); // _infop, retval
        when(mockNdrBuffer.dec_ndr_short()).thenReturn((int) (short) 0); // union discriminant

        queryInfoPolicy.decode_out(mockNdrBuffer);

        verify(mockInfo).decode(mockNdrBuffer);
        assertEquals(123, queryInfoPolicy.retval);
    }

    @Test
    void testLsarQueryInformationPolicyDecodeOutNullInfo() throws NdrException {
        rpc.policy_handle mockHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarQosInfo mockInfo = mock(lsarpc.LsarQosInfo.class);
        lsarpc.LsarQueryInformationPolicy queryInfoPolicy = new lsarpc.LsarQueryInformationPolicy(mockHandle, (short) 1, mockInfo);

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(0, 123); // _infop (null), retval

        queryInfoPolicy.decode_out(mockNdrBuffer);

        verify(mockInfo, never()).decode(any(NdrBuffer.class));
        assertEquals(123, queryInfoPolicy.retval);
    }

    // Test for LsarLookupSids
    @Test
    void testLsarLookupSidsConstructorAndGetOpnum() {
        rpc.policy_handle mockHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarSidArray mockSids = mock(lsarpc.LsarSidArray.class);
        lsarpc.LsarRefDomainList mockDomains = mock(lsarpc.LsarRefDomainList.class);
        lsarpc.LsarTransNameArray mockNames = mock(lsarpc.LsarTransNameArray.class);

        lsarpc.LsarLookupSids lookupSids = new lsarpc.LsarLookupSids(mockHandle, mockSids, mockDomains, mockNames, (short) 1, 10);

        assertEquals(mockHandle, lookupSids.handle);
        assertEquals(mockSids, lookupSids.sids);
        assertEquals(mockDomains, lookupSids.domains);
        assertEquals(mockNames, lookupSids.names);
        assertEquals(1, lookupSids.level);
        assertEquals(10, lookupSids.count);
        assertEquals(0x0f, lookupSids.getOpnum());
    }

    @Test
    void testLsarLookupSidsEncodeIn() throws NdrException {
        rpc.policy_handle mockHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarSidArray mockSids = mock(lsarpc.LsarSidArray.class);
        lsarpc.LsarRefDomainList mockDomains = mock(lsarpc.LsarRefDomainList.class);
        lsarpc.LsarTransNameArray mockNames = mock(lsarpc.LsarTransNameArray.class);

        lsarpc.LsarLookupSids lookupSids = new lsarpc.LsarLookupSids(mockHandle, mockSids, mockDomains, mockNames, (short) 1, 10);

        lookupSids.encode_in(mockNdrBuffer);

        verify(mockHandle).encode(mockNdrBuffer);
        verify(mockSids).encode(mockNdrBuffer);
        verify(mockNames).encode(mockNdrBuffer);
        verify(mockNdrBuffer).enc_ndr_short((short) 1);
        verify(mockNdrBuffer).enc_ndr_long(10);
    }

    @Test
    void testLsarLookupSidsDecodeOut() throws NdrException {
        rpc.policy_handle mockHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarSidArray mockSids = mock(lsarpc.LsarSidArray.class);
        lsarpc.LsarRefDomainList mockDomains = mock(lsarpc.LsarRefDomainList.class);
        lsarpc.LsarTransNameArray mockNames = mock(lsarpc.LsarTransNameArray.class);

        lsarpc.LsarLookupSids lookupSids = new lsarpc.LsarLookupSids(mockHandle, mockSids, mockDomains, mockNames, (short) 1, 10);

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 20, 123); // _domainsp, count, retval

        lookupSids.decode_out(mockNdrBuffer);

        verify(mockDomains).decode(mockNdrBuffer);
        verify(mockNames).decode(mockNdrBuffer);
        assertEquals(20, lookupSids.count);
        assertEquals(123, lookupSids.retval);
    }

    @Test
    void testLsarLookupSidsDecodeOutNullDomains() throws NdrException {
        rpc.policy_handle mockHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarSidArray mockSids = mock(lsarpc.LsarSidArray.class);
        lsarpc.LsarRefDomainList mockDomains = mock(lsarpc.LsarRefDomainList.class);
        lsarpc.LsarTransNameArray mockNames = mock(lsarpc.LsarTransNameArray.class);

        lsarpc.LsarLookupSids lookupSids = new lsarpc.LsarLookupSids(mockHandle, mockSids, mockDomains, mockNames, (short) 1, 10);

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(0, 20, 123); // _domainsp (null), count, retval

        lookupSids.decode_out(mockNdrBuffer);

        assertNotNull(lookupSids.domains); // Should be initialized by decode
        verify(mockDomains, never()).decode(any(NdrBuffer.class));
        verify(mockNames).decode(mockNdrBuffer);
        assertEquals(20, lookupSids.count);
        assertEquals(123, lookupSids.retval);
    }

    // Test for LsarOpenPolicy2
    @Test
    void testLsarOpenPolicy2ConstructorAndGetOpnum() {
        lsarpc.LsarObjectAttributes mockObjAttr = mock(lsarpc.LsarObjectAttributes.class);
        rpc.policy_handle mockPolicyHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarOpenPolicy2 openPolicy2 = new lsarpc.LsarOpenPolicy2("system", mockObjAttr, 1, mockPolicyHandle);

        assertEquals("system", openPolicy2.system_name);
        assertEquals(mockObjAttr, openPolicy2.object_attributes);
        assertEquals(1, openPolicy2.desired_access);
        assertEquals(mockPolicyHandle, openPolicy2.policy_handle);
        assertEquals(0x2c, openPolicy2.getOpnum());
    }

    @Test
    void testLsarOpenPolicy2EncodeIn() throws NdrException {
        lsarpc.LsarObjectAttributes mockObjAttr = mock(lsarpc.LsarObjectAttributes.class);
        rpc.policy_handle mockPolicyHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarOpenPolicy2 openPolicy2 = new lsarpc.LsarOpenPolicy2("system", mockObjAttr, 1, mockPolicyHandle);

        openPolicy2.encode_in(mockNdrBuffer);

        verify(mockNdrBuffer).enc_ndr_referent("system", 1);
        verify(mockNdrBuffer).enc_ndr_string("system");
        verify(mockObjAttr).encode(mockNdrBuffer);
        verify(mockNdrBuffer).enc_ndr_long(1);
    }

    @Test
    void testLsarOpenPolicy2EncodeInNullSystemName() throws NdrException {
        lsarpc.LsarObjectAttributes mockObjAttr = mock(lsarpc.LsarObjectAttributes.class);
        rpc.policy_handle mockPolicyHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarOpenPolicy2 openPolicy2 = new lsarpc.LsarOpenPolicy2(null, mockObjAttr, 1, mockPolicyHandle);

        openPolicy2.encode_in(mockNdrBuffer);

        verify(mockNdrBuffer).enc_ndr_referent(null, 1);
        verify(mockNdrBuffer, never()).enc_ndr_string(anyString());
        verify(mockObjAttr).encode(mockNdrBuffer);
        verify(mockNdrBuffer).enc_ndr_long(1);
    }

    @Test
    void testLsarOpenPolicy2DecodeOut() throws NdrException {
        lsarpc.LsarObjectAttributes mockObjAttr = mock(lsarpc.LsarObjectAttributes.class);
        rpc.policy_handle mockPolicyHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarOpenPolicy2 openPolicy2 = new lsarpc.LsarOpenPolicy2("system", mockObjAttr, 1, mockPolicyHandle);

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(123); // retval

        openPolicy2.decode_out(mockNdrBuffer);

        verify(mockPolicyHandle).decode(mockNdrBuffer);
        assertEquals(123, openPolicy2.retval);
    }

    // Test for LsarQueryInformationPolicy2
    @Test
    void testLsarQueryInformationPolicy2ConstructorAndGetOpnum() {
        rpc.policy_handle mockHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarQosInfo mockInfo = mock(lsarpc.LsarQosInfo.class);
        lsarpc.LsarQueryInformationPolicy2 queryInfoPolicy2 = new lsarpc.LsarQueryInformationPolicy2(mockHandle, (short) 1, mockInfo);

        assertEquals(mockHandle, queryInfoPolicy2.handle);
        assertEquals(1, queryInfoPolicy2.level);
        assertEquals(mockInfo, queryInfoPolicy2.info);
        assertEquals(0x2e, queryInfoPolicy2.getOpnum());
    }

    @Test
    void testLsarQueryInformationPolicy2EncodeIn() throws NdrException {
        rpc.policy_handle mockHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarQosInfo mockInfo = mock(lsarpc.LsarQosInfo.class);
        lsarpc.LsarQueryInformationPolicy2 queryInfoPolicy2 = new lsarpc.LsarQueryInformationPolicy2(mockHandle, (short) 1, mockInfo);

        queryInfoPolicy2.encode_in(mockNdrBuffer);

        verify(mockHandle).encode(mockNdrBuffer);
        verify(mockNdrBuffer).enc_ndr_short((short) 1);
    }

    @Test
    void testLsarQueryInformationPolicy2DecodeOut() throws NdrException {
        rpc.policy_handle mockHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarQosInfo mockInfo = mock(lsarpc.LsarQosInfo.class);
        lsarpc.LsarQueryInformationPolicy2 queryInfoPolicy2 = new lsarpc.LsarQueryInformationPolicy2(mockHandle, (short) 1, mockInfo);

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 123); // _infop, retval
        when(mockNdrBuffer.dec_ndr_short()).thenReturn((int) (short) 0); // union discriminant

        queryInfoPolicy2.decode_out(mockNdrBuffer);

        verify(mockInfo).decode(mockNdrBuffer);
        assertEquals(123, queryInfoPolicy2.retval);
    }

    @Test
    void testLsarQueryInformationPolicy2DecodeOutNullInfo() throws NdrException {
        rpc.policy_handle mockHandle = mock(rpc.policy_handle.class);
        lsarpc.LsarQosInfo mockInfo = mock(lsarpc.LsarQosInfo.class);
        lsarpc.LsarQueryInformationPolicy2 queryInfoPolicy2 = new lsarpc.LsarQueryInformationPolicy2(mockHandle, (short) 1, mockInfo);

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(0, 123); // _infop (null), retval

        queryInfoPolicy2.decode_out(mockNdrBuffer);

        verify(mockInfo, never()).decode(any(NdrBuffer.class));
        assertEquals(123, queryInfoPolicy2.retval);
    }
}
