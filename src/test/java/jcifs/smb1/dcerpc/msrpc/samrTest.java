package jcifs.smb1.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.smb1.dcerpc.rpc;
import jcifs.smb1.dcerpc.ndr.NdrBuffer;
import jcifs.smb1.dcerpc.ndr.NdrException;

/**
 * Comprehensive test suite for SMB1 samr (Security Account Manager Remote) protocol
 * Tests all message types, data structures, and constants
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SMB1 SAMR Protocol Test Suite")
class samrTest {

    @Mock
    private NdrBuffer mockNdrBuffer;

    @Mock
    private NdrBuffer mockDeferredBuffer;

    @Mock
    private rpc.policy_handle mockPolicyHandle;

    @Mock
    private rpc.sid_t mockSidT;

    @Mock
    private rpc.unicode_string mockUnicodeString;

    @Mock
    private lsarpc.LsarSidArray mockLsarSidArray;

    @BeforeEach
    void setUp() {
        // Directly set the deferred field on the mock
        mockNdrBuffer.deferred = mockDeferredBuffer;

        // Configure mocks for NdrBuffer interactions
        lenient().when(mockDeferredBuffer.derive(anyInt())).thenReturn(mockDeferredBuffer);
        lenient().doNothing().when(mockDeferredBuffer).advance(anyInt());
        // Set up index field for derive operations
        mockDeferredBuffer.index = 0;
    }

    @Nested
    @DisplayName("Protocol Information Tests")
    class ProtocolInfoTests {

        @Test
        @DisplayName("Should return correct syntax string")
        void testGetSyntax() {
            // When/Then: Verify the protocol syntax identifier
            assertEquals("12345778-1234-abcd-ef00-0123456789ac:1.0", samr.getSyntax());
        }
    }

    @Nested
    @DisplayName("Constants Tests")
    class ConstantsTests {

        @Test
        @DisplayName("Should define correct ACB (Account Control Block) constants")
        void testACBConstants() {
            // Verify all ACB constants
            assertEquals(1, samr.ACB_DISABLED);
            assertEquals(2, samr.ACB_HOMDIRREQ);
            assertEquals(4, samr.ACB_PWNOTREQ);
            assertEquals(8, samr.ACB_TEMPDUP);
            assertEquals(16, samr.ACB_NORMAL);
            assertEquals(32, samr.ACB_MNS);
            assertEquals(64, samr.ACB_DOMTRUST);
            assertEquals(128, samr.ACB_WSTRUST);
            assertEquals(256, samr.ACB_SVRTRUST);
            assertEquals(512, samr.ACB_PWNOEXP);
            assertEquals(1024, samr.ACB_AUTOLOCK);
            assertEquals(2048, samr.ACB_ENC_TXT_PWD_ALLOWED);
            assertEquals(4096, samr.ACB_SMARTCARD_REQUIRED);
            assertEquals(8192, samr.ACB_TRUSTED_FOR_DELEGATION);
            assertEquals(16384, samr.ACB_NOT_DELEGATED);
            assertEquals(32768, samr.ACB_USE_DES_KEY_ONLY);
            assertEquals(65536, samr.ACB_DONT_REQUIRE_PREAUTH);
        }

        @Test
        @DisplayName("Should define correct SE_GROUP constants")
        void testSEGroupConstants() {
            // Verify all SE_GROUP constants
            assertEquals(1, samr.SE_GROUP_MANDATORY);
            assertEquals(2, samr.SE_GROUP_ENABLED_BY_DEFAULT);
            assertEquals(4, samr.SE_GROUP_ENABLED);
            assertEquals(8, samr.SE_GROUP_OWNER);
            assertEquals(16, samr.SE_GROUP_USE_FOR_DENY_ONLY);
            assertEquals(536870912, samr.SE_GROUP_RESOURCE);
            assertEquals(-1073741824, samr.SE_GROUP_LOGON_ID);
        }
    }

    @Nested
    @DisplayName("SamrCloseHandle Tests")
    class SamrCloseHandleTests {

        @Test
        @DisplayName("Should construct with correct opnum")
        void testConstructorAndOpnum() {
            // When: Creating close handle message
            samr.SamrCloseHandle message = new samr.SamrCloseHandle(mockPolicyHandle);

            // Then: Should have correct opnum and handle
            assertEquals(0x01, message.getOpnum());
            assertEquals(mockPolicyHandle, message.handle);
        }

        @Test
        @DisplayName("Should encode input parameters correctly")
        void testEncodeIn() throws NdrException {
            // Given: Close handle message
            samr.SamrCloseHandle message = new samr.SamrCloseHandle(mockPolicyHandle);

            // When: Encoding input
            message.encode_in(mockNdrBuffer);

            // Then: Should encode handle
            verify(mockPolicyHandle).encode(mockNdrBuffer);
        }

        @Test
        @DisplayName("Should decode output parameters correctly")
        void testDecodeOut() throws NdrException {
            // Given: Close handle message with mocked return value
            samr.SamrCloseHandle message = new samr.SamrCloseHandle(mockPolicyHandle);
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(0);

            // When: Decoding output
            message.decode_out(mockNdrBuffer);

            // Then: Should decode return value
            verify(mockNdrBuffer).dec_ndr_long();
            assertEquals(0, message.retval);
        }
    }

    @Nested
    @DisplayName("SamrConnect2 Tests")
    class SamrConnect2Tests {

        @Test
        @DisplayName("Should construct with correct parameters and opnum")
        void testConstructorAndOpnum() {
            // When: Creating connect2 message
            samr.SamrConnect2 message = new samr.SamrConnect2("system", 123, mockPolicyHandle);

            // Then: Should have correct values
            assertEquals(0x39, message.getOpnum());
            assertEquals("system", message.system_name);
            assertEquals(123, message.access_mask);
            assertEquals(mockPolicyHandle, message.handle);
        }

        @Test
        @DisplayName("Should encode input with non-null system name")
        void testEncodeIn() throws NdrException {
            // Given: Connect2 message with system name
            samr.SamrConnect2 message = new samr.SamrConnect2("system", 123, mockPolicyHandle);

            // When: Encoding input
            message.encode_in(mockNdrBuffer);

            // Then: Should encode all parameters
            verify(mockNdrBuffer).enc_ndr_referent("system", 1);
            verify(mockNdrBuffer).enc_ndr_string("system");
            verify(mockNdrBuffer).enc_ndr_long(123);
        }

        @Test
        @DisplayName("Should encode input with null system name")
        void testEncodeInNullSystemName() throws NdrException {
            // Given: Connect2 message with null system name
            samr.SamrConnect2 message = new samr.SamrConnect2(null, 123, mockPolicyHandle);

            // When: Encoding input
            message.encode_in(mockNdrBuffer);

            // Then: Should encode null referent and access mask
            verify(mockNdrBuffer).enc_ndr_referent(null, 1);
            verify(mockNdrBuffer, never()).enc_ndr_string(anyString());
            verify(mockNdrBuffer).enc_ndr_long(123);
        }

        @Test
        @DisplayName("Should decode output correctly")
        void testDecodeOut() throws NdrException {
            // Given: Connect2 message with mocked return value
            samr.SamrConnect2 message = new samr.SamrConnect2("system", 123, mockPolicyHandle);
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(0);

            // When: Decoding output
            message.decode_out(mockNdrBuffer);

            // Then: Should decode handle and return value
            verify(mockPolicyHandle).decode(mockNdrBuffer);
            verify(mockNdrBuffer).dec_ndr_long();
            assertEquals(0, message.retval);
        }
    }

    @Nested
    @DisplayName("SamrConnect4 Tests")
    class SamrConnect4Tests {

        @Test
        @DisplayName("Should construct with correct parameters and opnum")
        void testConstructorAndOpnum() {
            // When: Creating connect4 message
            samr.SamrConnect4 message = new samr.SamrConnect4("system", 456, 123, mockPolicyHandle);

            // Then: Should have correct values
            assertEquals(0x3e, message.getOpnum());
            assertEquals("system", message.system_name);
            assertEquals(456, message.unknown);
            assertEquals(123, message.access_mask);
            assertEquals(mockPolicyHandle, message.handle);
        }

        @Test
        @DisplayName("Should encode input with non-null system name")
        void testEncodeIn() throws NdrException {
            // Given: Connect4 message
            samr.SamrConnect4 message = new samr.SamrConnect4("system", 456, 123, mockPolicyHandle);

            // When: Encoding input
            message.encode_in(mockNdrBuffer);

            // Then: Should encode all parameters
            verify(mockNdrBuffer).enc_ndr_referent("system", 1);
            verify(mockNdrBuffer).enc_ndr_string("system");
            verify(mockNdrBuffer).enc_ndr_long(456);
            verify(mockNdrBuffer).enc_ndr_long(123);
        }

        @Test
        @DisplayName("Should encode input with null system name")
        void testEncodeInNullSystemName() throws NdrException {
            // Given: Connect4 message with null system name
            samr.SamrConnect4 message = new samr.SamrConnect4(null, 456, 123, mockPolicyHandle);

            // When: Encoding input
            message.encode_in(mockNdrBuffer);

            // Then: Should encode null referent and other parameters
            verify(mockNdrBuffer).enc_ndr_referent(null, 1);
            verify(mockNdrBuffer, never()).enc_ndr_string(anyString());
            verify(mockNdrBuffer).enc_ndr_long(456);
            verify(mockNdrBuffer).enc_ndr_long(123);
        }

        @Test
        @DisplayName("Should decode output correctly")
        void testDecodeOut() throws NdrException {
            // Given: Connect4 message with mocked return value
            samr.SamrConnect4 message = new samr.SamrConnect4("system", 456, 123, mockPolicyHandle);
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(0);

            // When: Decoding output
            message.decode_out(mockNdrBuffer);

            // Then: Should decode handle and return value
            verify(mockPolicyHandle).decode(mockNdrBuffer);
            verify(mockNdrBuffer).dec_ndr_long();
            assertEquals(0, message.retval);
        }
    }

    @Nested
    @DisplayName("SamrOpenDomain Tests")
    class SamrOpenDomainTests {

        @Test
        @DisplayName("Should construct with correct parameters and opnum")
        void testConstructorAndOpnum() {
            // When: Creating open domain message
            samr.SamrOpenDomain message = new samr.SamrOpenDomain(mockPolicyHandle, 123, mockSidT, mockPolicyHandle);

            // Then: Should have correct values
            assertEquals(0x07, message.getOpnum());
            assertEquals(mockPolicyHandle, message.handle);
            assertEquals(123, message.access_mask);
            assertEquals(mockSidT, message.sid);
            assertEquals(mockPolicyHandle, message.domain_handle);
        }

        @Test
        @DisplayName("Should encode input correctly")
        void testEncodeIn() throws NdrException {
            // Given: Open domain message
            samr.SamrOpenDomain message = new samr.SamrOpenDomain(mockPolicyHandle, 123, mockSidT, mockPolicyHandle);

            // When: Encoding input
            message.encode_in(mockNdrBuffer);

            // Then: Should encode all parameters
            verify(mockPolicyHandle).encode(mockNdrBuffer);
            verify(mockNdrBuffer).enc_ndr_long(123);
            verify(mockSidT).encode(mockNdrBuffer);
        }

        @Test
        @DisplayName("Should decode output correctly")
        void testDecodeOut() throws NdrException {
            // Given: Open domain message with mocked return value
            samr.SamrOpenDomain message = new samr.SamrOpenDomain(mockPolicyHandle, 123, mockSidT, mockPolicyHandle);
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(0);

            // When: Decoding output
            message.decode_out(mockNdrBuffer);

            // Then: Should decode domain handle and return value
            verify(mockPolicyHandle).decode(mockNdrBuffer);
            verify(mockNdrBuffer).dec_ndr_long();
            assertEquals(0, message.retval);
        }
    }

    @Nested
    @DisplayName("SamrSamEntry Tests")
    class SamrSamEntryTests {

        @Test
        @DisplayName("Should encode entry with non-null buffer")
        void testEncode() throws NdrException {
            // Given: SAM entry with data
            samr.SamrSamEntry entry = new samr.SamrSamEntry();
            entry.idx = 1;
            entry.name = new rpc.unicode_string();
            entry.name.length = 4;
            entry.name.maximum_length = 6;
            entry.name.buffer = new short[] { 't', 'e', 's', 't' };

            // When: Encoding entry
            entry.encode(mockNdrBuffer);

            // Then: Should encode all fields
            verify(mockNdrBuffer).align(4);
            verify(mockNdrBuffer).enc_ndr_long(1);
            verify(mockNdrBuffer).enc_ndr_short((short) 4);
            verify(mockNdrBuffer).enc_ndr_short((short) 6);
            verify(mockNdrBuffer).enc_ndr_referent(entry.name.buffer, 1);
        }

        @Test
        @DisplayName("Should encode entry with null buffer")
        void testEncodeNullBuffer() throws NdrException {
            // Given: SAM entry with null buffer
            samr.SamrSamEntry entry = new samr.SamrSamEntry();
            entry.idx = 1;
            entry.name = new rpc.unicode_string();
            entry.name.length = 0;
            entry.name.maximum_length = 0;
            entry.name.buffer = null;

            // When: Encoding entry
            entry.encode(mockNdrBuffer);

            // Then: Should encode with null buffer
            verify(mockNdrBuffer).align(4);
            verify(mockNdrBuffer).enc_ndr_long(1);
            verify(mockNdrBuffer, times(2)).enc_ndr_short((short) 0); // length and maximum_length both 0
            verify(mockNdrBuffer).enc_ndr_referent(null, 1);
        }

        @Test
        @DisplayName("Should decode entry correctly")
        void testDecode() throws NdrException {
            // Given: Mocked buffer data
            samr.SamrSamEntry entry = new samr.SamrSamEntry();
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 100); // idx, _name_bufferp
            when(mockNdrBuffer.dec_ndr_short()).thenReturn(4, 6); // length, maximum_length
            when(mockDeferredBuffer.dec_ndr_long()).thenReturn(3, 0, 2); // _name_buffers, 0, _name_bufferl
            when(mockDeferredBuffer.dec_ndr_short()).thenReturn((int) (short) 't', (int) (short) 'e');

            // When: Decoding entry
            entry.decode(mockNdrBuffer);

            // Then: Verify structure
            assertEquals(1, entry.idx);
            assertNotNull(entry.name);
            assertEquals(4, entry.name.length);
            assertEquals(6, entry.name.maximum_length);
        }

        @Test
        @DisplayName("Should decode entry with null buffer pointer")
        void testDecodeNullBufferPointer() throws NdrException {
            // Given: Mocked buffer data with null pointer
            samr.SamrSamEntry entry = new samr.SamrSamEntry();
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 0); // idx, _name_bufferp = 0
            when(mockNdrBuffer.dec_ndr_short()).thenReturn(0, 0); // length, maximum_length

            // When: Decoding entry
            entry.decode(mockNdrBuffer);

            // Then: Should have null buffer
            assertEquals(1, entry.idx);
            assertNotNull(entry.name);
            assertNull(entry.name.buffer);
        }

        @Test
        @DisplayName("Should throw exception for invalid conformance")
        void testDecodeInvalidConformance() throws NdrException {
            // Given: Mocked buffer data with invalid conformance
            samr.SamrSamEntry entry = new samr.SamrSamEntry();
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 100); // idx, _name_bufferp
            when(mockNdrBuffer.dec_ndr_short()).thenReturn(4, 6); // length, maximum_length
            when(mockDeferredBuffer.dec_ndr_long()).thenReturn(-1); // Invalid _name_buffers

            // When/Then: Should throw exception
            NdrException thrown = assertThrows(NdrException.class, () -> entry.decode(mockNdrBuffer));
            assertEquals(NdrException.INVALID_CONFORMANCE, thrown.getMessage());
        }
    }

    @Nested
    @DisplayName("SamrSamArray Tests")
    class SamrSamArrayTests {

        @Test
        @DisplayName("Should encode array with entries")
        void testEncode() throws NdrException {
            // Given: SAM array with one entry
            samr.SamrSamArray array = new samr.SamrSamArray();
            array.count = 1;
            samr.SamrSamEntry entry = new samr.SamrSamEntry();
            entry.name = new rpc.unicode_string();
            array.entries = new samr.SamrSamEntry[] { entry };

            // When: Encoding array
            array.encode(mockNdrBuffer);

            // Then: Should encode structure
            verify(mockNdrBuffer).align(4);
            verify(mockNdrBuffer).enc_ndr_long(1);
            verify(mockNdrBuffer).enc_ndr_referent(array.entries, 1);
        }

        @Test
        @DisplayName("Should encode array with null entries")
        void testEncodeNullEntries() throws NdrException {
            // Given: SAM array with null entries
            samr.SamrSamArray array = new samr.SamrSamArray();
            array.count = 0;
            array.entries = null;

            // When: Encoding array
            array.encode(mockNdrBuffer);

            // Then: Should encode null referent
            verify(mockNdrBuffer).align(4);
            verify(mockNdrBuffer).enc_ndr_long(0);
            verify(mockNdrBuffer).enc_ndr_referent(null, 1);
        }

        @Test
        @DisplayName("Should decode array correctly")
        void testDecode() throws NdrException {
            // Given: Mocked buffer data with pre-created entries to avoid complex entry decode chain
            samr.SamrSamArray array = new samr.SamrSamArray();
            array.entries = new samr.SamrSamEntry[1]; // Pre-populate to avoid decoding
            array.entries[0] = new samr.SamrSamEntry();

            when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 100); // count, _entriesp
            when(mockDeferredBuffer.dec_ndr_long()).thenReturn(1); // _entriess
            // Setup deferred buffer chain for entry decoding
            mockDeferredBuffer.deferred = mockDeferredBuffer;
            when(mockDeferredBuffer.dec_ndr_short()).thenReturn(0, 0, 0); // SamrSamEntry fields

            // When: Decoding array
            array.decode(mockNdrBuffer);

            // Then: Should have entries
            assertEquals(1, array.count);
            assertNotNull(array.entries);
            assertEquals(1, array.entries.length);
        }

        @Test
        @DisplayName("Should decode array with null entries pointer")
        void testDecodeNullEntriesPointer() throws NdrException {
            // Given: Mocked buffer with null pointer
            samr.SamrSamArray array = new samr.SamrSamArray();
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(0, 0); // count, _entriesp = 0

            // When: Decoding array
            array.decode(mockNdrBuffer);

            // Then: Should have null entries
            assertEquals(0, array.count);
            assertNull(array.entries);
        }

        @Test
        @DisplayName("Should throw exception for invalid conformance")
        void testDecodeInvalidConformance() throws NdrException {
            // Given: Mocked buffer data with invalid conformance
            samr.SamrSamArray array = new samr.SamrSamArray();
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 100); // count, _entriesp
            when(mockDeferredBuffer.dec_ndr_long()).thenReturn(-1); // Invalid _entriess

            // When/Then: Should throw exception
            NdrException thrown = assertThrows(NdrException.class, () -> array.decode(mockNdrBuffer));
            assertEquals(NdrException.INVALID_CONFORMANCE, thrown.getMessage());
        }
    }

    @Nested
    @DisplayName("SamrEnumerateAliasesInDomain Tests")
    class SamrEnumerateAliasesInDomainTests {

        @Test
        @DisplayName("Should construct with correct parameters and opnum")
        void testConstructorAndOpnum() {
            // When: Creating enumerate aliases message
            samr.SamrEnumerateAliasesInDomain message =
                    new samr.SamrEnumerateAliasesInDomain(mockPolicyHandle, 1, 2, new samr.SamrSamArray(), 3);

            // Then: Should have correct values
            assertEquals(0x0f, message.getOpnum());
            assertEquals(mockPolicyHandle, message.domain_handle);
            assertEquals(1, message.resume_handle);
            assertEquals(2, message.acct_flags);
            assertNotNull(message.sam);
            assertEquals(3, message.num_entries);
        }

        @Test
        @DisplayName("Should encode input correctly")
        void testEncodeIn() throws NdrException {
            // Given: Enumerate aliases message
            samr.SamrEnumerateAliasesInDomain message =
                    new samr.SamrEnumerateAliasesInDomain(mockPolicyHandle, 1, 2, new samr.SamrSamArray(), 3);

            // When: Encoding input
            message.encode_in(mockNdrBuffer);

            // Then: Should encode parameters
            verify(mockPolicyHandle).encode(mockNdrBuffer);
            verify(mockNdrBuffer).enc_ndr_long(1);
            verify(mockNdrBuffer).enc_ndr_long(2);
        }

        @Test
        @DisplayName("Should decode output correctly")
        void testDecodeOut() throws NdrException {
            // Given: Enumerate aliases message with spy for sam
            samr.SamrSamArray samArray = spy(new samr.SamrSamArray());
            // Pre-populate entries to avoid complex decode chain
            samArray.entries = new samr.SamrSamEntry[1];
            samArray.entries[0] = new samr.SamrSamEntry();

            samr.SamrEnumerateAliasesInDomain message = new samr.SamrEnumerateAliasesInDomain(mockPolicyHandle, 1, 2, samArray, 3);
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(10, 100, 1, 100, 5, 0); // resume_handle, _samp, SamrSamArray.count, _entriesp, num_entries, retval
            when(mockDeferredBuffer.dec_ndr_long()).thenReturn(1); // SamrSamArray._entriess
            // Setup for SamrSamEntry decode chain
            mockDeferredBuffer.deferred = mockDeferredBuffer;
            when(mockDeferredBuffer.dec_ndr_short()).thenReturn(0, 0, 0);

            // When: Decoding output
            message.decode_out(mockNdrBuffer);

            // Then: Should decode all output parameters
            verify(samArray).decode(mockNdrBuffer);
            assertEquals(10, message.resume_handle);
            assertEquals(5, message.num_entries);
            assertEquals(0, message.retval);
        }

        @Test
        @DisplayName("Should handle null sam in decode")
        void testDecodeOutNullSam() throws NdrException {
            // Given: Message with null sam
            samr.SamrEnumerateAliasesInDomain message = new samr.SamrEnumerateAliasesInDomain(mockPolicyHandle, 1, 2, null, 3);
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(10, 100, 1, 100, 5, 0); // resume_handle, _samp, sam.count, sam._entriesp, num_entries, retval
            when(mockDeferredBuffer.dec_ndr_long()).thenReturn(1); // SamrSamArray._entriess
            // Setup for SamrSamEntry decode chain
            mockDeferredBuffer.deferred = mockDeferredBuffer;
            when(mockDeferredBuffer.dec_ndr_short()).thenReturn(0, 0, 0);

            // When: Decoding output
            message.decode_out(mockNdrBuffer);

            // Then: Should create sam instance
            assertNotNull(message.sam);
            assertEquals(10, message.resume_handle);
            assertEquals(5, message.num_entries);
            assertEquals(0, message.retval);
        }

        @Test
        @DisplayName("Should handle zero sam pointer correctly")
        void testDecodeOutZeroSamPointer() throws NdrException {
            // Given: Message with non-null sam and zero pointer in response
            samr.SamrSamArray samArray = spy(new samr.SamrSamArray());
            samr.SamrEnumerateAliasesInDomain message = new samr.SamrEnumerateAliasesInDomain(mockPolicyHandle, 1, 2, samArray, 3);
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(10, 0, 5, 0); // _samp = 0

            // When: Decoding output
            message.decode_out(mockNdrBuffer);

            // Then: Should not decode sam when pointer is zero
            verify(samArray, never()).decode(any());
            assertEquals(10, message.resume_handle);
            assertEquals(5, message.num_entries);
            assertEquals(0, message.retval);
        }
    }

    @Nested
    @DisplayName("SamrOpenAlias Tests")
    class SamrOpenAliasTests {

        @Test
        @DisplayName("Should construct with correct parameters and opnum")
        void testConstructorAndOpnum() {
            // When: Creating open alias message
            samr.SamrOpenAlias message = new samr.SamrOpenAlias(mockPolicyHandle, 123, 456, mockPolicyHandle);

            // Then: Should have correct values
            assertEquals(0x1b, message.getOpnum());
            assertEquals(mockPolicyHandle, message.domain_handle);
            assertEquals(123, message.access_mask);
            assertEquals(456, message.rid);
            assertEquals(mockPolicyHandle, message.alias_handle);
        }

        @Test
        @DisplayName("Should encode input correctly")
        void testEncodeIn() throws NdrException {
            // Given: Open alias message
            samr.SamrOpenAlias message = new samr.SamrOpenAlias(mockPolicyHandle, 123, 456, mockPolicyHandle);

            // When: Encoding input
            message.encode_in(mockNdrBuffer);

            // Then: Should encode all parameters
            verify(mockPolicyHandle).encode(mockNdrBuffer);
            verify(mockNdrBuffer).enc_ndr_long(123);
            verify(mockNdrBuffer).enc_ndr_long(456);
        }

        @Test
        @DisplayName("Should decode output correctly")
        void testDecodeOut() throws NdrException {
            // Given: Open alias message with mocked return value
            samr.SamrOpenAlias message = new samr.SamrOpenAlias(mockPolicyHandle, 123, 456, mockPolicyHandle);
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(0);

            // When: Decoding output
            message.decode_out(mockNdrBuffer);

            // Then: Should decode alias handle and return value
            verify(mockPolicyHandle).decode(mockNdrBuffer);
            verify(mockNdrBuffer).dec_ndr_long();
            assertEquals(0, message.retval);
        }
    }

    @Nested
    @DisplayName("SamrGetMembersInAlias Tests")
    class SamrGetMembersInAliasTests {

        @Test
        @DisplayName("Should construct with correct parameters and opnum")
        void testConstructorAndOpnum() {
            // When: Creating get members message
            samr.SamrGetMembersInAlias message = new samr.SamrGetMembersInAlias(mockPolicyHandle, mockLsarSidArray);

            // Then: Should have correct values
            assertEquals(0x21, message.getOpnum());
            assertEquals(mockPolicyHandle, message.alias_handle);
            assertEquals(mockLsarSidArray, message.sids);
        }

        @Test
        @DisplayName("Should encode input correctly")
        void testEncodeIn() throws NdrException {
            // Given: Get members message
            samr.SamrGetMembersInAlias message = new samr.SamrGetMembersInAlias(mockPolicyHandle, mockLsarSidArray);

            // When: Encoding input
            message.encode_in(mockNdrBuffer);

            // Then: Should encode alias handle
            verify(mockPolicyHandle).encode(mockNdrBuffer);
        }

        @Test
        @DisplayName("Should decode output correctly")
        void testDecodeOut() throws NdrException {
            // Given: Get members message with mocked return value
            samr.SamrGetMembersInAlias message = new samr.SamrGetMembersInAlias(mockPolicyHandle, mockLsarSidArray);
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(0);

            // When: Decoding output
            message.decode_out(mockNdrBuffer);

            // Then: Should decode sids array and return value
            verify(mockLsarSidArray).decode(mockNdrBuffer);
            verify(mockNdrBuffer).dec_ndr_long();
            assertEquals(0, message.retval);
        }
    }

    @Nested
    @DisplayName("SamrRidWithAttribute Tests")
    class SamrRidWithAttributeTests {

        @Test
        @DisplayName("Should encode RID with attribute correctly")
        void testEncode() throws NdrException {
            // Given: RID with attribute
            samr.SamrRidWithAttribute ridWithAttribute = new samr.SamrRidWithAttribute();
            ridWithAttribute.rid = 100;
            ridWithAttribute.attributes = 200;

            // When: Encoding
            ridWithAttribute.encode(mockNdrBuffer);

            // Then: Should encode both fields
            verify(mockNdrBuffer).align(4);
            verify(mockNdrBuffer).enc_ndr_long(100);
            verify(mockNdrBuffer).enc_ndr_long(200);
        }

        @Test
        @DisplayName("Should decode RID with attribute correctly")
        void testDecode() throws NdrException {
            // Given: RID with attribute and mocked data
            samr.SamrRidWithAttribute ridWithAttribute = new samr.SamrRidWithAttribute();
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(100, 200);

            // When: Decoding
            ridWithAttribute.decode(mockNdrBuffer);

            // Then: Should decode both fields
            verify(mockNdrBuffer).align(4);
            verify(mockNdrBuffer, times(2)).dec_ndr_long();
            assertEquals(100, ridWithAttribute.rid);
            assertEquals(200, ridWithAttribute.attributes);
        }
    }

    @Nested
    @DisplayName("SamrRidWithAttributeArray Tests")
    class SamrRidWithAttributeArrayTests {

        @Test
        @DisplayName("Should encode array with RIDs")
        void testEncode() throws NdrException {
            // Given: Array with one RID
            samr.SamrRidWithAttributeArray array = new samr.SamrRidWithAttributeArray();
            array.count = 1;
            array.rids = new samr.SamrRidWithAttribute[] { new samr.SamrRidWithAttribute() };

            // When: Encoding array
            array.encode(mockNdrBuffer);

            // Then: Should encode structure
            verify(mockNdrBuffer).align(4);
            verify(mockNdrBuffer).enc_ndr_long(1);
            verify(mockNdrBuffer).enc_ndr_referent(array.rids, 1);
        }

        @Test
        @DisplayName("Should encode array with null RIDs")
        void testEncodeNullRids() throws NdrException {
            // Given: Array with null RIDs
            samr.SamrRidWithAttributeArray array = new samr.SamrRidWithAttributeArray();
            array.count = 0;
            array.rids = null;

            // When: Encoding array
            array.encode(mockNdrBuffer);

            // Then: Should encode null referent
            verify(mockNdrBuffer).align(4);
            verify(mockNdrBuffer).enc_ndr_long(0);
            verify(mockNdrBuffer).enc_ndr_referent(null, 1);
        }

        @Test
        @DisplayName("Should decode array correctly")
        void testDecode() throws NdrException {
            // Given: Mocked buffer data
            samr.SamrRidWithAttributeArray array = new samr.SamrRidWithAttributeArray();
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 100); // count, _ridsp
            when(mockDeferredBuffer.dec_ndr_long()).thenReturn(1); // _ridss

            // When: Decoding array
            array.decode(mockNdrBuffer);

            // Then: Should have RIDs
            assertEquals(1, array.count);
            assertNotNull(array.rids);
            assertEquals(1, array.rids.length);
        }

        @Test
        @DisplayName("Should decode array with null RIDs pointer")
        void testDecodeNullRidsPointer() throws NdrException {
            // Given: Mocked buffer with null pointer
            samr.SamrRidWithAttributeArray array = new samr.SamrRidWithAttributeArray();
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(0, 0); // count, _ridsp = 0

            // When: Decoding array
            array.decode(mockNdrBuffer);

            // Then: Should have null RIDs
            assertEquals(0, array.count);
            assertNull(array.rids);
        }

        @Test
        @DisplayName("Should throw exception for invalid conformance")
        void testDecodeInvalidConformance() throws NdrException {
            // Given: Mocked buffer data with invalid conformance
            samr.SamrRidWithAttributeArray array = new samr.SamrRidWithAttributeArray();
            when(mockNdrBuffer.dec_ndr_long()).thenReturn(1, 100); // count, _ridsp
            when(mockDeferredBuffer.dec_ndr_long()).thenReturn(-1); // Invalid _ridss

            // When/Then: Should throw exception
            NdrException thrown = assertThrows(NdrException.class, () -> array.decode(mockNdrBuffer));
            assertEquals(NdrException.INVALID_CONFORMANCE, thrown.getMessage());
        }
    }
}