package jcifs.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;

/**
 * Test class for srvsvc.java classes
 */
class srvsvcTest {

    @Mock
    private NdrBuffer mockNdrBuffer;

    @Mock
    private NdrBuffer mockDeferredBuffer;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        // Set the deferred field directly since it's a public field, not a method
        mockNdrBuffer.deferred = mockDeferredBuffer;
        lenient().when(mockNdrBuffer.derive(anyInt())).thenReturn(mockDeferredBuffer);
        lenient().when(mockDeferredBuffer.derive(anyInt())).thenReturn(mockDeferredBuffer);
    }

    @Test
    void testGetSyntax() {
        String syntax = srvsvc.getSyntax();
        assertEquals("4b324fc8-1670-01d3-1278-5a47bf6ee188:3.0", syntax);
    }

    @Test
    void testShareInfo0EncodeWithNonNullNetname() throws NdrException {
        srvsvc.ShareInfo0 shareInfo0 = new srvsvc.ShareInfo0();
        shareInfo0.netname = "TestShare";

        shareInfo0.encode(mockNdrBuffer);

        // Verify the encode operations
        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_referent("TestShare", 1);
        verify(mockDeferredBuffer).enc_ndr_string("TestShare");
    }

    @Test
    void testShareInfo0EncodeWithNullNetname() throws NdrException {
        srvsvc.ShareInfo0 shareInfo0 = new srvsvc.ShareInfo0();
        shareInfo0.netname = null;

        shareInfo0.encode(mockNdrBuffer);

        // Verify the encode operations
        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_referent(null, 1);
        // Should not encode string if netname is null
        verify(mockDeferredBuffer, never()).enc_ndr_string(anyString());
    }

    @Test
    void testShareInfo0DecodeWithNonNullNetname() throws NdrException {
        srvsvc.ShareInfo0 shareInfo0 = new srvsvc.ShareInfo0();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(1); // non-zero pointer
        when(mockDeferredBuffer.dec_ndr_string()).thenReturn("DecodedShare");

        shareInfo0.decode(mockNdrBuffer);

        assertEquals("DecodedShare", shareInfo0.netname);
        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).dec_ndr_long();
        verify(mockDeferredBuffer).dec_ndr_string();
    }

    @Test
    void testShareInfo0DecodeWithNullNetname() throws NdrException {
        srvsvc.ShareInfo0 shareInfo0 = new srvsvc.ShareInfo0();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(0); // null pointer

        shareInfo0.decode(mockNdrBuffer);

        assertNull(shareInfo0.netname);
        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).dec_ndr_long();
        // Should not decode string if pointer is null
        verify(mockDeferredBuffer, never()).dec_ndr_string();
    }

    @Test
    void testShareInfo1EncodeWithAllFields() throws NdrException {
        srvsvc.ShareInfo1 shareInfo1 = new srvsvc.ShareInfo1();
        shareInfo1.netname = "TestShare";
        shareInfo1.type = 1;
        shareInfo1.remark = "Test Remark";

        // Set up deferred buffer chain to avoid NPE
        mockDeferredBuffer.deferred = mockDeferredBuffer;

        shareInfo1.encode(mockNdrBuffer);

        // Verify the encode operations
        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_referent("TestShare", 1);
        verify(mockNdrBuffer).enc_ndr_long(1);
        verify(mockNdrBuffer).enc_ndr_referent("Test Remark", 1);
        verify(mockDeferredBuffer, times(2)).enc_ndr_string(anyString());
    }

    @Test
    void testShareInfo1EncodeWithNullFields() throws NdrException {
        srvsvc.ShareInfo1 shareInfo1 = new srvsvc.ShareInfo1();
        shareInfo1.netname = null;
        shareInfo1.type = 0;
        shareInfo1.remark = null;

        shareInfo1.encode(mockNdrBuffer);

        // Verify the encode operations
        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer, times(2)).enc_ndr_referent(null, 1); // Called twice for netname and remark
        verify(mockNdrBuffer).enc_ndr_long(0);
        // Should not encode strings if fields are null
        verify(mockDeferredBuffer, never()).enc_ndr_string(anyString());
    }

    @Test
    void testShareInfo1DecodeWithAllFields() throws NdrException {
        srvsvc.ShareInfo1 shareInfo1 = new srvsvc.ShareInfo1();

        // Set up deferred buffer chain to avoid NPE
        mockDeferredBuffer.deferred = mockDeferredBuffer;

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 2, 1); // netname pointer, type, remark pointer
        when(mockDeferredBuffer.dec_ndr_string()).thenReturn("DecodedShare", "Decoded Remark");

        shareInfo1.decode(mockNdrBuffer);

        assertEquals("DecodedShare", shareInfo1.netname);
        assertEquals(2, shareInfo1.type);
        assertEquals("Decoded Remark", shareInfo1.remark);
        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer, times(3)).dec_ndr_long();
        verify(mockDeferredBuffer, times(2)).dec_ndr_string();
    }

    @Test
    void testShareInfo502EncodeWithAllFields() throws NdrException {
        srvsvc.ShareInfo502 shareInfo502 = new srvsvc.ShareInfo502();
        shareInfo502.netname = "TestShare";
        shareInfo502.type = 1;
        shareInfo502.remark = "Test Remark";
        shareInfo502.permissions = 2;
        shareInfo502.max_uses = 10;
        shareInfo502.current_uses = 5;
        shareInfo502.path = "C:\\test";
        shareInfo502.password = "password";
        shareInfo502.sd_size = 2;
        shareInfo502.security_descriptor = new byte[] { 1, 2 };

        // Set up mocks for the security descriptor encoding
        mockDeferredBuffer.index = 0; // Set field directly
        mockDeferredBuffer.deferred = mockDeferredBuffer;

        shareInfo502.encode(mockNdrBuffer);

        // Verify the encode operations
        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_referent("TestShare", 1);
        verify(mockNdrBuffer).enc_ndr_long(1); // type
        verify(mockNdrBuffer).enc_ndr_referent("Test Remark", 1);
        verify(mockNdrBuffer, times(2)).enc_ndr_long(2); // permissions and sd_size both have value 2
        verify(mockNdrBuffer).enc_ndr_long(10); // max_uses
        verify(mockNdrBuffer).enc_ndr_long(5); // current_uses
        verify(mockNdrBuffer).enc_ndr_referent("C:\\test", 1);
        verify(mockNdrBuffer).enc_ndr_referent("password", 1);
        verify(mockNdrBuffer).enc_ndr_referent(shareInfo502.security_descriptor, 1);

        // Verify string encodings
        verify(mockDeferredBuffer, times(4)).enc_ndr_string(anyString());

        // Verify security descriptor encoding
        verify(mockDeferredBuffer).enc_ndr_long(2);
        verify(mockDeferredBuffer).advance(2);
        verify(mockDeferredBuffer).enc_ndr_small((byte) 1);
        verify(mockDeferredBuffer).enc_ndr_small((byte) 2);
    }

    @Test
    void testShareInfoCtr0EncodeWithArray() throws NdrException {
        srvsvc.ShareInfoCtr0 ctr0 = new srvsvc.ShareInfoCtr0();
        ctr0.count = 2;
        ctr0.array = new srvsvc.ShareInfo0[2];
        ctr0.array[0] = new srvsvc.ShareInfo0();
        ctr0.array[0].netname = "Share1";
        ctr0.array[1] = new srvsvc.ShareInfo0();
        ctr0.array[1].netname = "Share2";

        // Set up mocks
        mockDeferredBuffer.index = 0; // Set field directly
        mockDeferredBuffer.deferred = mockDeferredBuffer;

        ctr0.encode(mockNdrBuffer);

        // Verify the encode operations
        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_long(2);
        verify(mockNdrBuffer).enc_ndr_referent(ctr0.array, 1);
        verify(mockDeferredBuffer).enc_ndr_long(2);
        verify(mockDeferredBuffer).advance(8); // 4 * 2
    }

    @Test
    void testShareInfoCtr0DecodeWithArray() throws NdrException {
        srvsvc.ShareInfoCtr0 ctr0 = new srvsvc.ShareInfoCtr0();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(2, 1); // count, array pointer
        when(mockDeferredBuffer.dec_ndr_long()).thenReturn(2); // array size
        mockDeferredBuffer.index = 0; // Set field directly
        mockDeferredBuffer.deferred = mockDeferredBuffer;

        ctr0.decode(mockNdrBuffer);

        assertEquals(2, ctr0.count);
        assertNotNull(ctr0.array);
        assertEquals(2, ctr0.array.length);
        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer, times(2)).dec_ndr_long();
        verify(mockDeferredBuffer, times(3)).dec_ndr_long(); // 1 for array size + 2 for ShareInfo0 decode calls
        verify(mockDeferredBuffer).advance(8); // 4 * 2
    }

    @Test
    void testShareInfoCtr1EncodeWithArray() throws NdrException {
        srvsvc.ShareInfoCtr1 ctr1 = new srvsvc.ShareInfoCtr1();
        ctr1.count = 2;
        ctr1.array = new srvsvc.ShareInfo1[2];
        ctr1.array[0] = new srvsvc.ShareInfo1();
        ctr1.array[0].netname = "Share1";
        ctr1.array[0].type = 0;
        ctr1.array[0].remark = "Remark1";
        ctr1.array[1] = new srvsvc.ShareInfo1();
        ctr1.array[1].netname = "Share2";
        ctr1.array[1].type = 1;
        ctr1.array[1].remark = "Remark2";

        // Set up mocks
        mockDeferredBuffer.index = 0; // Set field directly
        mockDeferredBuffer.deferred = mockDeferredBuffer;

        ctr1.encode(mockNdrBuffer);

        // Verify the encode operations
        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_long(2);
        verify(mockNdrBuffer).enc_ndr_referent(ctr1.array, 1);
        verify(mockDeferredBuffer).enc_ndr_long(2);
        verify(mockDeferredBuffer).advance(24); // 12 * 2
    }

    @Test
    void testShareInfoCtr502EncodeWithEmptyArray() throws NdrException {
        srvsvc.ShareInfoCtr502 ctr502 = new srvsvc.ShareInfoCtr502();
        ctr502.count = 0;
        ctr502.array = null;

        ctr502.encode(mockNdrBuffer);

        // Verify the encode operations
        verify(mockNdrBuffer).align(4);
        verify(mockNdrBuffer).enc_ndr_long(0);
        verify(mockNdrBuffer).enc_ndr_referent(null, 1);
        // Should not encode array if it's null
        verify(mockDeferredBuffer, never()).enc_ndr_long(anyInt());
    }

    @Test
    void testShareInfoCtr502DecodeWithInvalidArraySize() throws NdrException {
        srvsvc.ShareInfoCtr502 ctr502 = new srvsvc.ShareInfoCtr502();

        when(mockNdrBuffer.dec_ndr_long()).thenReturn(10, 1); // count, array pointer
        when(mockDeferredBuffer.dec_ndr_long()).thenReturn(0x10000); // invalid array size

        assertThrows(NdrException.class, () -> ctr502.decode(mockNdrBuffer));
    }

    @Test
    void testShareEnumAllConstructor() {
        String servername = "\\\\SERVER";
        int level = 1;
        srvsvc.ShareInfoCtr1 info = new srvsvc.ShareInfoCtr1();
        int prefmaxlen = 0xFFFFFFFF;
        int totalentries = 0;
        int resume_handle = 0;

        srvsvc.ShareEnumAll enumAll = new srvsvc.ShareEnumAll(servername, level, info, prefmaxlen, totalentries, resume_handle);

        assertEquals(servername, enumAll.servername);
        assertEquals(level, enumAll.level);
        assertEquals(info, enumAll.info);
        assertEquals(prefmaxlen, enumAll.prefmaxlen);
        assertEquals(totalentries, enumAll.totalentries);
        assertEquals(resume_handle, enumAll.resume_handle);
    }

    @Test
    void testShareEnumAllGetOpnum() {
        srvsvc.ShareEnumAll enumAll = new srvsvc.ShareEnumAll(null, 0, null, 0, 0, 0);
        assertEquals(0x0f, enumAll.getOpnum());
    }
}