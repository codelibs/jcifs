package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The response to the NT_TRANSACT_QUERY_SECURITY_DESC request that {@code getSecurity} and {@code getOwnerUser} send.
 *
 * <p>
 * The descriptor bytes come from {@link SecurityDescriptorTest}, which lays them out from the specification.
 * </p>
 */
class NtTransQuerySecurityDescResponseTest {

    @Test
    @DisplayName("the data block decodes into the security descriptor")
    void dataDecodesTheDescriptor() {
        final byte[] descriptor = SecurityDescriptorTest.descriptor(SecurityDescriptorTest.OWNER, null, SecurityDescriptorTest
                .acl(SecurityDescriptorTest.ace(SecurityDescriptorTest.DENIED, 0, ACE.FILE_READ_DATA, SecurityDescriptorTest.EVERYONE)));
        final byte[] buffer = new byte[5 + descriptor.length];
        System.arraycopy(descriptor, 0, buffer, 5, descriptor.length);
        final NtTransQuerySecurityDescResponse response = new NtTransQuerySecurityDescResponse();

        final int read = response.readDataWireFormat(buffer, 5, descriptor.length);

        assertEquals(descriptor.length, read);
        assertEquals(SecurityDescriptorTest.OWNER, response.securityDescriptor.owner_user.toString());
        assertEquals(1, response.securityDescriptor.aces.length);
        assertFalse(response.securityDescriptor.aces[0].isAllow());
        assertEquals(SecurityDescriptorTest.EVERYONE, response.securityDescriptor.aces[0].getSID().toString());
    }

    @Test
    @DisplayName("an error response carries no descriptor")
    void errorResponseCarriesNoDescriptor() {
        final NtTransQuerySecurityDescResponse response = new NtTransQuerySecurityDescResponse();
        response.errorCode = NtStatus.NT_STATUS_ACCESS_DENIED;

        assertEquals(4, response.readDataWireFormat(new byte[64], 0, 64));
        assertNull(response.securityDescriptor);
    }

    @Test
    @DisplayName("the parameter block carries the length of the descriptor")
    void parametersCarryTheLength() {
        final byte[] buffer = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(0x1234).array();
        final NtTransQuerySecurityDescResponse response = new NtTransQuerySecurityDescResponse();

        assertEquals(4, response.readParametersWireFormat(buffer, 0, 4));
        assertEquals(0x1234, response.length);
    }

    @Test
    @DisplayName("a malformed descriptor fails the read")
    void malformedDescriptorFailsTheRead() {
        final byte[] header = ByteBuffer.allocate(8)
                .order(ByteOrder.LITTLE_ENDIAN)
                .put((byte) 2)
                .put((byte) 0)
                .putShort((short) 8)
                .putShort((short) 4097)
                .putShort((short) 0)
                .array();
        final byte[] descriptor = SecurityDescriptorTest.descriptor(null, null, header);
        final NtTransQuerySecurityDescResponse response = new NtTransQuerySecurityDescResponse();

        assertThrows(RuntimeException.class, () -> response.readDataWireFormat(descriptor, 0, descriptor.length));
    }
}
