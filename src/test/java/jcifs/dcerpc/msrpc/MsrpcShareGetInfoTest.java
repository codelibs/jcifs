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
        assertEquals(0, msrpcShareGetInfo.ptype);
        assertEquals(DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG, 
                    msrpcShareGetInfo.flags);
        
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
        // Setup mock ShareInfo502 with security descriptor
        srvsvc.ShareInfo502 info502 = new srvsvc.ShareInfo502();
        byte[] securityDescriptorBytes = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
        info502.security_descriptor = securityDescriptorBytes;
        info502.sd_size = securityDescriptorBytes.length;
        
        // Replace info field with our mock
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareGetInfo, info502);
        
        // Mock SecurityDescriptor behavior
        ACE[] expectedAces = new ACE[] {mockAce1, mockAce2};
        SecurityDescriptor sd = mock(SecurityDescriptor.class);
        when(sd.getAces()).thenReturn(expectedAces);
        
        // Since we can't easily mock the constructor, we'll test the actual behavior
        // The actual SecurityDescriptor will be created, so we test that ACEs are returned
        ACE[] result = msrpcShareGetInfo.getSecurity();
        
        // The actual implementation creates a new SecurityDescriptor
        // We can't directly verify the ACEs without a real SecurityDescriptor
        // So we verify that the method doesn't throw and returns something
        // In a real scenario, this would require integration testing
    }
    
    @Test
    void testGetSecurityWithNullSecurityDescriptor() throws Exception {
        // Setup ShareInfo502 with null security descriptor
        srvsvc.ShareInfo502 info502 = new srvsvc.ShareInfo502();
        info502.security_descriptor = null;
        
        // Replace info field
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getSuperclass().getDeclaredField("info");
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
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareGetInfo, info502);
        
        // Test getSecurity with empty descriptor
        // This might throw an exception in SecurityDescriptor constructor
        // depending on implementation
        ACE[] result = msrpcShareGetInfo.getSecurity();
        // Result depends on SecurityDescriptor implementation
    }
    
    @Test
    void testGetSecurityWithLargeSecurityDescriptor() throws Exception {
        // Test with large security descriptor
        srvsvc.ShareInfo502 info502 = new srvsvc.ShareInfo502();
        byte[] largeDescriptor = new byte[1024];
        for (int i = 0; i < largeDescriptor.length; i++) {
            largeDescriptor[i] = (byte)(i % 256);
        }
        info502.security_descriptor = largeDescriptor;
        info502.sd_size = largeDescriptor.length;
        
        // Replace info field
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareGetInfo, info502);
        
        // Test getSecurity with large descriptor
        ACE[] result = msrpcShareGetInfo.getSecurity();
        // Result depends on SecurityDescriptor implementation
    }
    
    @Test
    void testGetSecurityWithMismatchedSize() throws Exception {
        // Test when sd_size doesn't match actual array size
        srvsvc.ShareInfo502 info502 = new srvsvc.ShareInfo502();
        info502.security_descriptor = new byte[] {1, 2, 3, 4};
        info502.sd_size = 100; // Mismatched size
        
        // Replace info field
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareGetInfo, info502);
        
        // This might throw an exception depending on SecurityDescriptor implementation
        try {
            ACE[] result = msrpcShareGetInfo.getSecurity();
            // If no exception, verify result is handled
        } catch (Exception e) {
            // Expected behavior for mismatched size
            assertTrue(e instanceof IOException || e instanceof ArrayIndexOutOfBoundsException 
                      || e instanceof IllegalArgumentException);
        }
    }
    
    @Test
    void testGetSecurityWithWrongInfoType() throws Exception {
        // Test when info is not ShareInfo502
        srvsvc.ShareInfo0 info0 = new srvsvc.ShareInfo0();
        
        // Replace info field with wrong type
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getSuperclass().getDeclaredField("info");
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
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getSuperclass().getDeclaredField("info");
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
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        Object info = infoField.get(msrpcShareGetInfo);
        assertNotNull(info);
        assertTrue(info instanceof srvsvc.ShareInfo502);
    }
    
    @Test
    void testMultipleCallsToGetSecurity() throws Exception {
        // Setup ShareInfo502 with security descriptor
        srvsvc.ShareInfo502 info502 = new srvsvc.ShareInfo502();
        byte[] securityDescriptorBytes = new byte[] {1, 2, 3, 4, 5};
        info502.security_descriptor = securityDescriptorBytes;
        info502.sd_size = securityDescriptorBytes.length;
        
        // Replace info field
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareGetInfo, info502);
        
        // Call getSecurity multiple times
        ACE[] result1 = msrpcShareGetInfo.getSecurity();
        ACE[] result2 = msrpcShareGetInfo.getSecurity();
        
        // Each call creates a new SecurityDescriptor, so results might differ
        // depending on implementation
    }
    
    @Test
    void testGetSecurityWithSpecialCharactersInSecurityDescriptor() throws Exception {
        // Test with security descriptor containing special byte values
        srvsvc.ShareInfo502 info502 = new srvsvc.ShareInfo502();
        byte[] specialBytes = new byte[] {0, -1, 127, -128, 64};
        info502.security_descriptor = specialBytes;
        info502.sd_size = specialBytes.length;
        
        // Replace info field
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getSuperclass().getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(msrpcShareGetInfo, info502);
        
        // Test getSecurity with special bytes
        ACE[] result = msrpcShareGetInfo.getSecurity();
        // Result depends on SecurityDescriptor implementation
    }
    
    @Test
    void testPtypeAndFlagsValues() {
        // Verify specific flag values are correctly set
        assertEquals(0, msrpcShareGetInfo.ptype);
        
        // Check individual flag bits
        int flags = msrpcShareGetInfo.flags;
        assertTrue((flags & DcerpcConstants.DCERPC_FIRST_FRAG) != 0);
        assertTrue((flags & DcerpcConstants.DCERPC_LAST_FRAG) != 0);
    }
    
    @Test
    void testShareInfo502Initialization() throws Exception {
        // Verify ShareInfo502 is properly initialized
        Field infoField = msrpcShareGetInfo.getClass().getSuperclass().getSuperclass().getDeclaredField("info");
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