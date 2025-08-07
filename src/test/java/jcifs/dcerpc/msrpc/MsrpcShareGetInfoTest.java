package jcifs.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.doThrow;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Constructor;

import jcifs.dcerpc.DcerpcConstants;
import jcifs.internal.dtyp.ACE;
import jcifs.internal.dtyp.SecurityDescriptor;

@ExtendWith(MockitoExtension.class)
class MsrpcShareGetInfoTest {

    @Mock
    private srvsvc.ShareInfo502 mockShareInfo502;
    
    @Mock
    private SecurityDescriptor mockSecurityDescriptor;
    
    @Mock
    private ACE mockAce1;
    
    @Mock
    private ACE mockAce2;
    
    private MsrpcShareGetInfo msrpcShareGetInfo;
    private String testServer = "testServer";
    private String testSharename = "testShare";
    
    @BeforeEach
    void setUp() {
        msrpcShareGetInfo = new MsrpcShareGetInfo(testServer, testSharename);
    }
    
    @Test
    void testConstructor() {
        // Verify constructor properly initializes the object
        assertNotNull(msrpcShareGetInfo);
        assertEquals(0, msrpcShareGetInfo.getPtype());
        assertEquals(DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG, 
                    msrpcShareGetInfo.getFlags());
        
        // Verify parent class initialization
        assertNotNull(msrpcShareGetInfo.info);
        assertTrue(msrpcShareGetInfo.info instanceof srvsvc.ShareInfo502);
        assertEquals(502, msrpcShareGetInfo.level);
        assertEquals(testServer, msrpcShareGetInfo.servername);
        assertEquals(testSharename, msrpcShareGetInfo.sharename);
    }
    
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"", "share1", "\\\\server\\share", "C$", "ADMIN$", "IPC$"})
    void testConstructorWithDifferentSharenames(String sharename) {
        // Test with various sharename values
        MsrpcShareGetInfo shareGetInfo = new MsrpcShareGetInfo(testServer, sharename);
        assertNotNull(shareGetInfo);
        assertEquals(sharename, shareGetInfo.sharename);
        assertEquals(testServer, shareGetInfo.servername);
    }
    
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"", "localhost", "192.168.1.1", "server.domain.com", "\\\\server"})
    void testConstructorWithDifferentServers(String server) {
        // Test with various server values
        MsrpcShareGetInfo shareGetInfo = new MsrpcShareGetInfo(server, testSharename);
        assertNotNull(shareGetInfo);
        assertEquals(server, shareGetInfo.servername);
        assertEquals(testSharename, shareGetInfo.sharename);
    }
    
    @Test
    void testGetSecurityWithValidSecurityDescriptor() throws Exception {
        // Setup mock ShareInfo502 with a minimal valid security descriptor
        srvsvc.ShareInfo502 info502 = new srvsvc.ShareInfo502();
        // Create a minimal valid security descriptor binary
        // Format: revision(1) + sbz1(1) + control(2) + ownerOffset(4) + groupOffset(4) + saclOffset(4) + daclOffset(4) = 20 bytes minimum
        byte[] securityDescriptorBytes = new byte[20];
        securityDescriptorBytes[0] = 1; // revision
        securityDescriptorBytes[1] = 0; // sbz1
        // control flags (2 bytes)
        securityDescriptorBytes[2] = 0;
        securityDescriptorBytes[3] = 0;
        // No owner, group, sacl, or dacl (all offsets are 0)
        // Rest of bytes are already 0
        
        info502.security_descriptor = securityDescriptorBytes;
        info502.sd_size = securityDescriptorBytes.length;
        
        // Replace info field
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareGetInfo, info502);
        
        // Test getSecurity - with no DACL, it should return null
        ACE[] result = msrpcShareGetInfo.getSecurity();
        assertNull(result);
    }
    
    @Test
    void testGetSecurityWithDACL() throws Exception {
        // Setup ShareInfo502 with a security descriptor containing a DACL with no ACEs
        srvsvc.ShareInfo502 info502 = new srvsvc.ShareInfo502();
        
        // Create a security descriptor with DACL at offset 20
        byte[] securityDescriptorBytes = new byte[28];
        securityDescriptorBytes[0] = 1; // revision
        securityDescriptorBytes[1] = 0; // sbz1
        securityDescriptorBytes[2] = 0; // control flags
        securityDescriptorBytes[3] = 0;
        // No owner (offset 0)
        for (int i = 4; i < 8; i++) securityDescriptorBytes[i] = 0;
        // No group (offset 0)
        for (int i = 8; i < 12; i++) securityDescriptorBytes[i] = 0;
        // No SACL (offset 0)
        for (int i = 12; i < 16; i++) securityDescriptorBytes[i] = 0;
        // DACL at offset 20
        securityDescriptorBytes[16] = 20;
        securityDescriptorBytes[17] = 0;
        securityDescriptorBytes[18] = 0;
        securityDescriptorBytes[19] = 0;
        
        // DACL header at offset 20
        securityDescriptorBytes[20] = 2; // ACL revision
        securityDescriptorBytes[21] = 0; // sbz1
        securityDescriptorBytes[22] = 8; // ACL size (low byte)
        securityDescriptorBytes[23] = 0; // ACL size (high byte)
        securityDescriptorBytes[24] = 0; // ACE count (low byte) - 0 ACEs
        securityDescriptorBytes[25] = 0; // ACE count (high byte)
        securityDescriptorBytes[26] = 0; // sbz2 (low byte)
        securityDescriptorBytes[27] = 0; // sbz2 (high byte)
        
        info502.security_descriptor = securityDescriptorBytes;
        info502.sd_size = securityDescriptorBytes.length;
        
        // Replace info field
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareGetInfo, info502);
        
        // Test getSecurity - DACL with 0 ACEs should return empty array
        ACE[] result = msrpcShareGetInfo.getSecurity();
        assertNotNull(result);
        assertEquals(0, result.length);
    }
    
    @Test
    void testGetSecurityWithNullSecurityDescriptor() throws Exception {
        // Setup ShareInfo502 with null security descriptor
        srvsvc.ShareInfo502 info502 = new srvsvc.ShareInfo502();
        info502.security_descriptor = null;
        
        // Replace info field
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareGetInfo, info502);
        
        // Test getSecurity returns null when security_descriptor is null
        ACE[] result = msrpcShareGetInfo.getSecurity();
        assertNull(result);
    }
    
    @Test
    void testGetSecurityWithEmptySecurityDescriptor() throws Exception {
        // Setup ShareInfo502 with empty security descriptor
        srvsvc.ShareInfo502 info502 = new srvsvc.ShareInfo502();
        info502.security_descriptor = new byte[0];
        info502.sd_size = 0;
        
        // Replace info field
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareGetInfo, info502);
        
        // Test getSecurity with empty descriptor - should throw exception
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            msrpcShareGetInfo.getSecurity();
        });
    }
    
    @Test
    void testGetSecurityWithLargeSecurityDescriptor() throws Exception {
        // Test with large valid security descriptor
        srvsvc.ShareInfo502 info502 = new srvsvc.ShareInfo502();
        // Create a valid but large security descriptor
        byte[] largeDescriptor = new byte[1024];
        largeDescriptor[0] = 1; // revision
        largeDescriptor[1] = 0; // sbz1
        // Set control flags
        largeDescriptor[2] = 0;
        largeDescriptor[3] = 0;
        // Set offsets to 0 (no owner, group, sacl, dacl)
        for (int i = 4; i < 20; i++) {
            largeDescriptor[i] = 0;
        }
        // Rest of the buffer can be arbitrary
        for (int i = 20; i < largeDescriptor.length; i++) {
            largeDescriptor[i] = (byte)(i % 256);
        }
        info502.security_descriptor = largeDescriptor;
        info502.sd_size = largeDescriptor.length;
        
        // Replace info field
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareGetInfo, info502);
        
        // Test getSecurity with large descriptor - should return null (no DACL)
        ACE[] result = msrpcShareGetInfo.getSecurity();
        assertNull(result);
    }
    
    @Test
    void testGetSecurityWithMismatchedSize() throws Exception {
        // Test when sd_size doesn't match actual array size
        srvsvc.ShareInfo502 info502 = new srvsvc.ShareInfo502();
        info502.security_descriptor = new byte[] {1, 2, 3, 4};
        info502.sd_size = 100; // Mismatched size - SecurityDescriptor will try to read beyond array bounds
        
        // Replace info field
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareGetInfo, info502);
        
        // This should throw an ArrayIndexOutOfBoundsException when trying to read beyond array
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            msrpcShareGetInfo.getSecurity();
        });
    }
    
    @Test
    void testGetSecurityWithWrongInfoType() throws Exception {
        // Test when info is not ShareInfo502
        srvsvc.ShareInfo0 info0 = new srvsvc.ShareInfo0();
        
        // Replace info field with wrong type
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareGetInfo, info0);
        
        // This should throw ClassCastException
        assertThrows(ClassCastException.class, () -> {
            msrpcShareGetInfo.getSecurity();
        });
    }
    
    @Test
    void testGetSecurityWhenInfoIsNull() throws Exception {
        // Test when info field is null
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareGetInfo, null);
        
        // This should throw NullPointerException
        assertThrows(NullPointerException.class, () -> {
            msrpcShareGetInfo.getSecurity();
        });
    }
    
    @Test
    void testInheritedFields() throws Exception {
        // Verify inherited fields are properly set
        assertEquals(0x10, msrpcShareGetInfo.getOpnum());
        
        // Test that the info field is properly initialized
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        Object info = infoField.get(msrpcShareGetInfo);
        assertNotNull(info);
        assertTrue(info instanceof srvsvc.ShareInfo502);
    }
    
    @Test
    void testMultipleCallsToGetSecurity() throws Exception {
        // Setup ShareInfo502 with valid security descriptor
        srvsvc.ShareInfo502 info502 = new srvsvc.ShareInfo502();
        byte[] securityDescriptorBytes = new byte[20];
        securityDescriptorBytes[0] = 1; // revision
        // Rest are zeros - no DACL
        info502.security_descriptor = securityDescriptorBytes;
        info502.sd_size = securityDescriptorBytes.length;
        
        // Replace info field
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareGetInfo, info502);
        
        // Call getSecurity multiple times - should return consistent results
        ACE[] result1 = msrpcShareGetInfo.getSecurity();
        ACE[] result2 = msrpcShareGetInfo.getSecurity();
        
        // Both should be null (no DACL)
        assertNull(result1);
        assertNull(result2);
    }
    
    @Test
    void testGetSecurityWithSpecialCharactersInSecurityDescriptor() throws Exception {
        // Test with security descriptor containing special byte values but invalid structure
        srvsvc.ShareInfo502 info502 = new srvsvc.ShareInfo502();
        byte[] specialBytes = new byte[] {0, -1, 127, -128, 64};
        info502.security_descriptor = specialBytes;
        info502.sd_size = specialBytes.length;
        
        // Replace info field
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareGetInfo, info502);
        
        // Test getSecurity with special bytes - should throw exception due to invalid format
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            msrpcShareGetInfo.getSecurity();
        });
    }
    
    @Test
    void testPtypeAndFlagsValues() {
        // Verify specific flag values are correctly set
        assertEquals(0, msrpcShareGetInfo.getPtype());
        
        // Check individual flag bits
        int flags = msrpcShareGetInfo.getFlags();
        assertTrue((flags & DcerpcConstants.DCERPC_FIRST_FRAG) != 0);
        assertTrue((flags & DcerpcConstants.DCERPC_LAST_FRAG) != 0);
    }
    
    @Test
    void testShareInfo502Initialization() throws Exception {
        // Verify ShareInfo502 is properly initialized
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        srvsvc.ShareInfo502 info502 = (srvsvc.ShareInfo502) infoField.get(msrpcShareGetInfo);
        
        assertNotNull(info502);
        // Initial state of ShareInfo502 fields
        assertNull(info502.netname);
        assertNull(info502.remark);
        assertNull(info502.path);
        assertNull(info502.password);
        assertNull(info502.security_descriptor);
        assertEquals(0, info502.type);
        assertEquals(0, info502.permissions);
        assertEquals(0, info502.max_uses);
        assertEquals(0, info502.current_uses);
        assertEquals(0, info502.sd_size);
    }
}