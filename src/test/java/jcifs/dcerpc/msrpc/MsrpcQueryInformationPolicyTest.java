package jcifs.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.any;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.dcerpc.DcerpcConstants;
import jcifs.dcerpc.ndr.NdrObject;
import jcifs.dcerpc.rpc;

@ExtendWith(MockitoExtension.class)
class MsrpcQueryInformationPolicyTest {

    @Mock
    private LsaPolicyHandle mockPolicyHandle;
    
    @Mock
    private NdrObject mockNdrObject;
    
    private MsrpcQueryInformationPolicy queryPolicy;
    
    @BeforeEach
    void setUp() {
        // Setup is done through individual test methods
    }
    
    @Test
    void constructor_shouldInitializeWithValidParameters() {
        // Arrange
        short level = 3;
        
        // Act
        queryPolicy = new MsrpcQueryInformationPolicy(mockPolicyHandle, level, mockNdrObject);
        
        // Assert
        assertNotNull(queryPolicy);
        assertEquals(0, queryPolicy.getPtype());
        assertEquals(DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG, queryPolicy.getFlags());
    }
    
    @Test
    void constructor_shouldSetHandleCorrectly() {
        // Arrange
        short level = 1;
        
        // Act
        queryPolicy = new MsrpcQueryInformationPolicy(mockPolicyHandle, level, mockNdrObject);
        
        // Assert
        assertSame(mockPolicyHandle, queryPolicy.handle);
    }
    
    @Test
    void constructor_shouldSetLevelCorrectly() {
        // Arrange
        short level = 7;
        
        // Act
        queryPolicy = new MsrpcQueryInformationPolicy(mockPolicyHandle, level, mockNdrObject);
        
        // Assert
        assertEquals(level, queryPolicy.level);
    }
    
    @Test
    void constructor_shouldSetInfoObjectCorrectly() {
        // Arrange
        short level = 2;
        
        // Act
        queryPolicy = new MsrpcQueryInformationPolicy(mockPolicyHandle, level, mockNdrObject);
        
        // Assert
        assertSame(mockNdrObject, queryPolicy.info);
    }
    
    @ParameterizedTest
    @ValueSource(shorts = {0, 1, 2, 3, 5, 10, Short.MAX_VALUE, Short.MIN_VALUE})
    void constructor_shouldAcceptVariousLevelValues(short level) {
        // Act
        queryPolicy = new MsrpcQueryInformationPolicy(mockPolicyHandle, level, mockNdrObject);
        
        // Assert
        assertNotNull(queryPolicy);
        assertEquals(level, queryPolicy.level);
    }
    
    @Test
    void constructor_shouldHandleNullPolicyHandle() {
        // Arrange
        LsaPolicyHandle nullHandle = null;
        short level = 1;
        
        // Act
        queryPolicy = new MsrpcQueryInformationPolicy(nullHandle, level, mockNdrObject);
        
        // Assert
        assertNotNull(queryPolicy);
        assertEquals(null, queryPolicy.handle);
    }
    
    @Test
    void constructor_shouldHandleNullNdrObject() {
        // Arrange
        short level = 1;
        NdrObject nullInfo = null;
        
        // Act
        queryPolicy = new MsrpcQueryInformationPolicy(mockPolicyHandle, level, nullInfo);
        
        // Assert
        assertNotNull(queryPolicy);
        assertEquals(null, queryPolicy.info);
    }
    
    @Test
    void constructor_shouldAlwaysSetPtypeToZero() {
        // Arrange
        short level = 5;
        
        // Act
        queryPolicy = new MsrpcQueryInformationPolicy(mockPolicyHandle, level, mockNdrObject);
        
        // Assert
        assertEquals(0, queryPolicy.getPtype());
    }
    
    @Test
    void constructor_shouldAlwaysSetFlagsToFirstAndLastFrag() {
        // Arrange
        short level = 4;
        int expectedFlags = DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG;
        
        // Act
        queryPolicy = new MsrpcQueryInformationPolicy(mockPolicyHandle, level, mockNdrObject);
        
        // Assert
        assertEquals(expectedFlags, queryPolicy.getFlags());
        // Binary check for individual flags
        assertEquals(0x03, queryPolicy.getFlags()); // 0x01 | 0x02 = 0x03
    }
    
    @Test
    void getOpnum_shouldReturnCorrectValue() {
        // Arrange
        short level = 1;
        queryPolicy = new MsrpcQueryInformationPolicy(mockPolicyHandle, level, mockNdrObject);
        
        // Act
        int opnum = queryPolicy.getOpnum();
        
        // Assert
        assertEquals(0x07, opnum); // Expected opnum for LsarQueryInformationPolicy
    }
    
    @Test
    void multipleInstances_shouldBeIndependent() {
        // Arrange
        short level1 = 1;
        short level2 = 2;
        NdrObject mockNdrObject2 = mock(NdrObject.class);
        LsaPolicyHandle mockPolicyHandle2 = mock(LsaPolicyHandle.class);
        
        // Act
        MsrpcQueryInformationPolicy queryPolicy1 = new MsrpcQueryInformationPolicy(mockPolicyHandle, level1, mockNdrObject);
        MsrpcQueryInformationPolicy queryPolicy2 = new MsrpcQueryInformationPolicy(mockPolicyHandle2, level2, mockNdrObject2);
        
        // Assert
        assertEquals(level1, queryPolicy1.level);
        assertEquals(level2, queryPolicy2.level);
        assertSame(mockPolicyHandle, queryPolicy1.handle);
        assertSame(mockPolicyHandle2, queryPolicy2.handle);
        assertSame(mockNdrObject, queryPolicy1.info);
        assertSame(mockNdrObject2, queryPolicy2.info);
    }
    
    @Test
    void constructor_shouldInitializeRetvalToZero() {
        // Arrange
        short level = 1;
        
        // Act
        queryPolicy = new MsrpcQueryInformationPolicy(mockPolicyHandle, level, mockNdrObject);
        
        // Assert
        assertEquals(0, queryPolicy.retval);
    }
    
    @Test
    void constructor_withMinimumShortValue() {
        // Arrange
        short level = Short.MIN_VALUE;
        
        // Act
        queryPolicy = new MsrpcQueryInformationPolicy(mockPolicyHandle, level, mockNdrObject);
        
        // Assert
        assertEquals(Short.MIN_VALUE, queryPolicy.level);
    }
    
    @Test
    void constructor_withMaximumShortValue() {
        // Arrange
        short level = Short.MAX_VALUE;
        
        // Act
        queryPolicy = new MsrpcQueryInformationPolicy(mockPolicyHandle, level, mockNdrObject);
        
        // Assert
        assertEquals(Short.MAX_VALUE, queryPolicy.level);
    }
    
    @Test
    void inheritance_shouldExtendLsarQueryInformationPolicy() {
        // Arrange
        short level = 1;
        
        // Act
        queryPolicy = new MsrpcQueryInformationPolicy(mockPolicyHandle, level, mockNdrObject);
        
        // Assert
        assertNotNull(queryPolicy);
        assertEquals(lsarpc.LsarQueryInformationPolicy.class, queryPolicy.getClass().getSuperclass());
    }
}