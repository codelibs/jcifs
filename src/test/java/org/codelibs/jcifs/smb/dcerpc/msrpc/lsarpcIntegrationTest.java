package org.codelibs.jcifs.smb.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.codelibs.jcifs.smb.dcerpc.rpc;
import org.codelibs.jcifs.smb.dcerpc.ndr.NdrBuffer;
import org.codelibs.jcifs.smb.dcerpc.ndr.NdrException;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for lsarpc classes using real NdrBuffer implementations
 */
class lsarpcIntegrationTest {

    @Test
    void testLsarDomainInfoEncodeDecodeRoundTrip() throws NdrException {
        // Create a domain info with test data
        lsarpc.LsarDomainInfo domainInfo = new lsarpc.LsarDomainInfo();
        domainInfo.name = new rpc.unicode_string();
        domainInfo.name.length = 10;
        domainInfo.name.maximum_length = 20;
        domainInfo.name.buffer = new short[] { 'T', 'e', 's', 't', '1' };

        // Create a simple test SIDObject
        domainInfo.sid = new rpc.sid_t();
        domainInfo.sid.revision = 1;
        domainInfo.sid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        domainInfo.sid.sub_authority_count = 2;
        domainInfo.sid.sub_authority = new int[] { 21, 12345 };

        // Encode to buffer
        byte[] buffer = new byte[1024];
        NdrBuffer encodeBuffer = new NdrBuffer(buffer, 0);
        domainInfo.encode(encodeBuffer);

        // Decode from buffer
        NdrBuffer decodeBuffer = new NdrBuffer(buffer, 0);
        lsarpc.LsarDomainInfo decodedInfo = new lsarpc.LsarDomainInfo();
        decodedInfo.decode(decodeBuffer);

        // Verify the decoded data matches
        assertEquals(domainInfo.name.length, decodedInfo.name.length);
        assertEquals(domainInfo.name.maximum_length, decodedInfo.name.maximum_length);
        assertNotNull(decodedInfo.name.buffer);
        assertEquals(domainInfo.name.maximum_length / 2, decodedInfo.name.buffer.length);

        // Verify SIDObject
        assertNotNull(decodedInfo.sid);
        assertEquals(domainInfo.sid.revision, decodedInfo.sid.revision);
        assertEquals(domainInfo.sid.sub_authority_count, decodedInfo.sid.sub_authority_count);
    }

    @Test
    void testLsarDomainInfoEncodeDecodeWithNulls() throws NdrException {
        // Create a domain info with null fields
        lsarpc.LsarDomainInfo domainInfo = new lsarpc.LsarDomainInfo();
        domainInfo.name = new rpc.unicode_string();
        domainInfo.name.buffer = null;
        domainInfo.sid = null;

        // Encode to buffer
        byte[] buffer = new byte[1024];
        NdrBuffer encodeBuffer = new NdrBuffer(buffer, 0);
        domainInfo.encode(encodeBuffer);

        // Decode from buffer
        NdrBuffer decodeBuffer = new NdrBuffer(buffer, 0);
        lsarpc.LsarDomainInfo decodedInfo = new lsarpc.LsarDomainInfo();
        decodedInfo.decode(decodeBuffer);

        // Verify nulls are preserved
        assertEquals(0, decodedInfo.name.length);
        assertEquals(0, decodedInfo.name.maximum_length);
        assertNull(decodedInfo.name.buffer);
        assertNull(decodedInfo.sid);
    }

    @Test
    void testLsarDnsDomainInfoEncodeDecodeRoundTrip() throws NdrException {
        // Create DNS domain info with test data
        lsarpc.LsarDnsDomainInfo dnsDomainInfo = new lsarpc.LsarDnsDomainInfo();

        dnsDomainInfo.name = new rpc.unicode_string();
        dnsDomainInfo.name.length = 8;
        dnsDomainInfo.name.maximum_length = 16;
        dnsDomainInfo.name.buffer = new short[] { 'T', 'E', 'S', 'T' };

        dnsDomainInfo.dns_domain = new rpc.unicode_string();
        dnsDomainInfo.dns_domain.length = 16;
        dnsDomainInfo.dns_domain.maximum_length = 32;
        dnsDomainInfo.dns_domain.buffer = new short[] { 't', 'e', 's', 't', '.', 'c', 'o', 'm' };

        dnsDomainInfo.dns_forest = new rpc.unicode_string();
        dnsDomainInfo.dns_forest.length = 12;
        dnsDomainInfo.dns_forest.maximum_length = 24;
        dnsDomainInfo.dns_forest.buffer = new short[] { 'f', 'o', 'r', 'e', 's', 't' };

        dnsDomainInfo.domain_guid = new rpc.uuid_t();
        dnsDomainInfo.domain_guid.time_low = 0x12345678;
        dnsDomainInfo.domain_guid.time_mid = 0x1234;
        dnsDomainInfo.domain_guid.time_hi_and_version = 0x5678;
        dnsDomainInfo.domain_guid.clock_seq_hi_and_reserved = 0x12;
        dnsDomainInfo.domain_guid.clock_seq_low = 0x34;
        dnsDomainInfo.domain_guid.node = new byte[] { 1, 2, 3, 4, 5, 6 };

        dnsDomainInfo.sid = new rpc.sid_t();
        dnsDomainInfo.sid.revision = 1;
        dnsDomainInfo.sid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        dnsDomainInfo.sid.sub_authority_count = 1;
        dnsDomainInfo.sid.sub_authority = new int[] { 21 };

        // Encode to buffer
        byte[] buffer = new byte[2048];
        NdrBuffer encodeBuffer = new NdrBuffer(buffer, 0);
        dnsDomainInfo.encode(encodeBuffer);

        // Decode from buffer
        NdrBuffer decodeBuffer = new NdrBuffer(buffer, 0);
        lsarpc.LsarDnsDomainInfo decodedInfo = new lsarpc.LsarDnsDomainInfo();
        decodedInfo.decode(decodeBuffer);

        // Verify the decoded data matches
        assertEquals(dnsDomainInfo.name.length, decodedInfo.name.length);
        assertEquals(dnsDomainInfo.dns_domain.length, decodedInfo.dns_domain.length);
        assertEquals(dnsDomainInfo.dns_forest.length, decodedInfo.dns_forest.length);

        // Verify GUID
        assertEquals(dnsDomainInfo.domain_guid.time_low, decodedInfo.domain_guid.time_low);
        assertEquals(dnsDomainInfo.domain_guid.time_mid, decodedInfo.domain_guid.time_mid);
        assertNotNull(decodedInfo.domain_guid.node);
        assertEquals(6, decodedInfo.domain_guid.node.length);

        // Verify SIDObject
        assertNotNull(decodedInfo.sid);
        assertEquals(dnsDomainInfo.sid.revision, decodedInfo.sid.revision);
    }

    @Test
    void testLsarTrustInformationEncodeDecodeRoundTrip() throws NdrException {
        // Create trust info with test data
        lsarpc.LsarTrustInformation trustInfo = new lsarpc.LsarTrustInformation();
        trustInfo.name = new rpc.unicode_string();
        trustInfo.name.length = 14;
        trustInfo.name.maximum_length = 28;
        trustInfo.name.buffer = new short[] { 'T', 'R', 'U', 'S', 'T', 'E', 'D' };

        trustInfo.sid = new rpc.sid_t();
        trustInfo.sid.revision = 1;
        trustInfo.sid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        trustInfo.sid.sub_authority_count = 3;
        trustInfo.sid.sub_authority = new int[] { 21, 123, 456 };

        // Encode to buffer
        byte[] buffer = new byte[1024];
        NdrBuffer encodeBuffer = new NdrBuffer(buffer, 0);
        trustInfo.encode(encodeBuffer);

        // Decode from buffer
        NdrBuffer decodeBuffer = new NdrBuffer(buffer, 0);
        lsarpc.LsarTrustInformation decodedInfo = new lsarpc.LsarTrustInformation();
        decodedInfo.decode(decodeBuffer);

        // Verify the decoded data matches
        assertEquals(trustInfo.name.length, decodedInfo.name.length);
        assertEquals(trustInfo.name.maximum_length, decodedInfo.name.maximum_length);
        assertNotNull(decodedInfo.name.buffer);

        // Verify SIDObject
        assertNotNull(decodedInfo.sid);
        assertEquals(trustInfo.sid.revision, decodedInfo.sid.revision);
        assertEquals(trustInfo.sid.sub_authority_count, decodedInfo.sid.sub_authority_count);
    }

    @Test
    void testLsarSidArrayEncodeDecodeRoundTrip() throws NdrException {
        // Create SIDObject array with test data
        lsarpc.LsarSidArray sidArray = new lsarpc.LsarSidArray();
        sidArray.num_sids = 2;
        sidArray.sids = new lsarpc.LsarSidPtr[2];

        sidArray.sids[0] = new lsarpc.LsarSidPtr();
        sidArray.sids[0].sid = new rpc.sid_t();
        sidArray.sids[0].sid.revision = 1;
        sidArray.sids[0].sid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        sidArray.sids[0].sid.sub_authority_count = 1;
        sidArray.sids[0].sid.sub_authority = new int[] { 500 };

        sidArray.sids[1] = new lsarpc.LsarSidPtr();
        sidArray.sids[1].sid = new rpc.sid_t();
        sidArray.sids[1].sid.revision = 1;
        sidArray.sids[1].sid.identifier_authority = new byte[] { 0, 0, 0, 0, 0, 5 };
        sidArray.sids[1].sid.sub_authority_count = 1;
        sidArray.sids[1].sid.sub_authority = new int[] { 501 };

        // Encode to buffer
        byte[] buffer = new byte[1024];
        NdrBuffer encodeBuffer = new NdrBuffer(buffer, 0);
        sidArray.encode(encodeBuffer);

        // Decode from buffer
        NdrBuffer decodeBuffer = new NdrBuffer(buffer, 0);
        lsarpc.LsarSidArray decodedArray = new lsarpc.LsarSidArray();
        decodedArray.decode(decodeBuffer);

        // Verify the decoded data matches
        assertEquals(sidArray.num_sids, decodedArray.num_sids);
        assertNotNull(decodedArray.sids);
        assertEquals(2, decodedArray.sids.length);

        // Verify first SIDObject
        assertNotNull(decodedArray.sids[0]);
        assertNotNull(decodedArray.sids[0].sid);
        assertEquals(500, decodedArray.sids[0].sid.sub_authority[0]);

        // Verify second SIDObject
        assertNotNull(decodedArray.sids[1]);
        assertNotNull(decodedArray.sids[1].sid);
        assertEquals(501, decodedArray.sids[1].sid.sub_authority[0]);
    }

    @Test
    void testLsarTranslatedNameEncodeDecodeRoundTrip() throws NdrException {
        // Create translated name with test data
        lsarpc.LsarTranslatedName translatedName = new lsarpc.LsarTranslatedName();
        translatedName.sid_type = 1;
        translatedName.name = new rpc.unicode_string();
        translatedName.name.length = 16;
        translatedName.name.maximum_length = 32;
        translatedName.name.buffer = new short[] { 'U', 's', 'e', 'r', 'N', 'a', 'm', 'e' };
        translatedName.sid_index = 42;

        // Encode to buffer
        byte[] buffer = new byte[1024];
        NdrBuffer encodeBuffer = new NdrBuffer(buffer, 0);
        translatedName.encode(encodeBuffer);

        // Decode from buffer
        NdrBuffer decodeBuffer = new NdrBuffer(buffer, 0);
        lsarpc.LsarTranslatedName decodedName = new lsarpc.LsarTranslatedName();
        decodedName.decode(decodeBuffer);

        // Verify the decoded data matches
        assertEquals(translatedName.sid_type, decodedName.sid_type);
        // The decode process doesn't preserve the original length, it reads from the buffer
        assertNotNull(decodedName.name);
        assertNotNull(decodedName.name.buffer);
        // Buffer length is based on maximum_length/2 from the encoded data
        assertEquals(translatedName.name.maximum_length / 2, decodedName.name.buffer.length);
        // Verify the actual string content
        for (int i = 0; i < translatedName.name.buffer.length; i++) {
            assertEquals(translatedName.name.buffer[i], decodedName.name.buffer[i]);
        }
        assertEquals(translatedName.sid_index, decodedName.sid_index);
    }
}