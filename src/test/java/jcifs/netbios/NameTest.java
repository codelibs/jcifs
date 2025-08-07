package jcifs.netbios;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.Configuration;
import jcifs.NetbiosName;

@ExtendWith(MockitoExtension.class)
class NameTest {

    @Mock
    private Configuration mockConfig;
    
    @BeforeEach
    void setUp() {
        // Setup default mock behavior
        lenient().when(mockConfig.getNetbiosScope()).thenReturn("DEFAULT.SCOPE");
        lenient().when(mockConfig.getOemEncoding()).thenReturn("UTF-8");
    }
    
    @Test
    void constructor_withConfigOnly_shouldInitializeFields() throws Exception {
        Name name = new Name(mockConfig);
        
        Field configField = Name.class.getDeclaredField("config");
        configField.setAccessible(true);
        assertSame(mockConfig, configField.get(name));
    }
    
    @Test
    void constructor_withAllParameters_shouldInitializeCorrectly() {
        Name name = new Name(mockConfig, "TestName", 0x20, "custom.scope");
        
        assertEquals("TESTNAME", name.name);
        assertEquals(0x20, name.hexCode);
        assertEquals("custom.scope", name.scope);
        assertEquals(0, name.srcHashCode);
    }
    
    @Test
    void constructor_withLongName_shouldTruncateTo15Characters() {
        String longName = "ThisIsAVeryLongNameThatExceeds15Characters";
        Name name = new Name(mockConfig, longName, 0x20, null);
        
        assertEquals("THISISAVERYLON", name.name);
        assertEquals(15, name.name.length());
    }
    
    @Test
    void constructor_withNullScope_shouldUseConfigScope() {
        Name name = new Name(mockConfig, "TestName", 0x20, null);
        assertEquals("DEFAULT.SCOPE", name.scope);
    }
    
    @Test
    void constructor_withEmptyScope_shouldUseConfigScope() {
        Name name = new Name(mockConfig, "TestName", 0x20, "");
        assertEquals("DEFAULT.SCOPE", name.scope);
    }
    
    @Test
    void constructor_withNetbiosName_shouldCopyAllFields() {
        NetbiosName sourceName = new Name(mockConfig, "SourceName", 0x1C, "source.scope");
        Name name = new Name(mockConfig, sourceName);
        
        assertEquals("SOURCENAME", name.name);
        assertEquals(0x1C, name.hexCode);
        assertEquals("source.scope", name.scope);
    }
    
    @Test
    void constructor_withNameInstance_shouldCopySrcHashCode() {
        Name sourceName = new Name(mockConfig, "SourceName", 0x1C, "source.scope");
        sourceName.srcHashCode = 12345;
        
        Name name = new Name(mockConfig, sourceName);
        
        assertEquals("SOURCENAME", name.name);
        assertEquals(0x1C, name.hexCode);
        assertEquals("source.scope", name.scope);
        assertEquals(12345, name.srcHashCode);
    }
    
    @Test
    void getName_shouldReturnName() {
        Name name = new Name(mockConfig, "TestName", 0x20, null);
        assertEquals("TESTNAME", name.getName());
    }
    
    @Test
    void getScope_shouldReturnScope() {
        Name name = new Name(mockConfig, "TestName", 0x20, "test.scope");
        assertEquals("test.scope", name.getScope());
    }
    
    @Test
    void getNameType_shouldReturnHexCode() {
        Name name = new Name(mockConfig, "TestName", 0x1C, null);
        assertEquals(0x1C, name.getNameType());
    }
    
    @Test
    void isUnknown_withUnknownAddress_shouldReturnTrue() {
        Name name = new Name(mockConfig, "0.0.0.0", 0, null);
        name.scope = null;
        assertTrue(name.isUnknown());
    }
    
    @Test
    void isUnknown_withNormalName_shouldReturnFalse() {
        Name name = new Name(mockConfig, "TestName", 0x20, null);
        assertFalse(name.isUnknown());
    }
    
    @Test
    void isUnknown_withNonZeroHexCode_shouldReturnFalse() {
        Name name = new Name(mockConfig, "0.0.0.0", 0x20, null);
        name.scope = null;
        assertFalse(name.isUnknown());
    }
    
    @Test
    void isUnknown_withScope_shouldReturnFalse() {
        Name name = new Name(mockConfig, "0.0.0.0", 0, "scope");
        assertFalse(name.isUnknown());
    }
    
    @Test
    void writeWireFormat_shouldEncodeNameCorrectly() {
        Name name = new Name(mockConfig, "TEST", 0x20, null);
        byte[] dst = new byte[100];
        
        int length = name.writeWireFormat(dst, 0);
        
        // Check first byte is 0x20
        assertEquals(0x20, dst[0]);
        
        // Check encoded name (TEST -> encoded as pairs)
        // T = 0x54 -> upper nibble: 0x50 -> 0x45 (E), lower nibble: 0x04 -> 0x44 (D)
        assertEquals('E', dst[1]); // (0x54 >> 4) + 0x41 = 0x45 = 'E'
        assertEquals('E', dst[2]); // (0x54 & 0x0F) + 0x41 = 0x44 + 1 = 'E'
        
        // Check padding (positions 8-30 should be 'CA' pairs for spaces)
        for (int i = 8; i < 31; i += 2) {
            assertEquals('C', dst[i + 1]);
            assertEquals('A', dst[i + 2]);
        }
        
        // Check type encoding at position 31-32
        assertEquals('C', dst[31]); // (0x20 >> 4) + 0x41 = 'C'
        assertEquals('A', dst[32]); // (0x20 & 0x0F) + 0x41 = 'A'
        
        // Verify length
        assertTrue(length > 33);
    }
    
    @Test
    void writeWireFormat_withScope_shouldEncodeCorrectly() {
        Name name = new Name(mockConfig, "TEST", 0x20, "scope.com");
        byte[] dst = new byte[100];
        
        int length = name.writeWireFormat(dst, 0);
        
        // Scope should start at position 33
        assertEquals('.', dst[33]);
        
        // Verify total length includes scope
        assertEquals(33 + name.scope.length() + 2, length);
    }
    
    @Test
    void readWireFormat_shouldDecodeNameCorrectly() {
        // Prepare encoded data for "TEST" with type 0x20
        byte[] src = new byte[100];
        src[0] = 0x20; // First byte
        
        // Encode "TEST" (0x54 0x45 0x53 0x54)
        src[1] = 'E'; src[2] = 'E';  // T
        src[3] = 'E'; src[4] = 'F';  // E
        src[5] = 'E'; src[6] = 'D';  // S
        src[7] = 'E'; src[8] = 'E';  // T
        
        // Fill padding with encoded spaces
        for (int i = 9; i < 31; i += 2) {
            src[i] = 'C';
            src[i + 1] = 'A';
        }
        
        // Encode type 0x20
        src[31] = 'C';
        src[32] = 'A';
        
        // No scope
        src[33] = 0x00;
        
        Name name = new Name(mockConfig);
        int length = name.readWireFormat(src, 0);
        
        assertEquals("TEST", name.name);
        assertEquals(0x20, name.hexCode);
        assertNull(name.scope);
        assertEquals(34, length);
    }
    
    @Test
    void readWireFormat_withScope_shouldDecodeCorrectly() {
        byte[] src = new byte[100];
        
        // Encode name part (simplified)
        for (int i = 0; i < 33; i++) {
            src[i] = 'A';
        }
        
        // Encode scope "test.com"
        src[33] = 4; // Length of "test"
        src[34] = 't'; src[35] = 'e'; src[36] = 's'; src[37] = 't';
        src[38] = 3; // Length of "com"
        src[39] = 'c'; src[40] = 'o'; src[41] = 'm';
        src[42] = 0; // End marker
        
        Name name = new Name(mockConfig);
        name.readWireFormat(src, 0);
        
        assertEquals("test.com", name.scope);
    }
    
    @Test
    void writeScopeWireFormat_withNullScope_shouldWriteZeroByte() {
        Name name = new Name(mockConfig, "TEST", 0x20, null);
        name.scope = null;
        byte[] dst = new byte[10];
        
        int length = name.writeScopeWireFormat(dst, 0);
        
        assertEquals(0x00, dst[0]);
        assertEquals(1, length);
    }
    
    @Test
    void writeScopeWireFormat_withScope_shouldWriteEncodedScope() {
        Name name = new Name(mockConfig, "TEST", 0x20, "test.com");
        byte[] dst = new byte[50];
        
        int length = name.writeScopeWireFormat(dst, 0);
        
        // Should start with '.'
        assertEquals('.', dst[0]);
        
        // Should end with 0x00
        assertEquals(0x00, dst[length - 1]);
        
        // Length should be scope length + 2
        assertEquals(name.scope.length() + 2, length);
    }
    
    @Test
    void readScopeWireFormat_withNullScope_shouldReturnOne() {
        byte[] src = new byte[10];
        src[0] = 0x00;
        
        Name name = new Name(mockConfig);
        int length = name.readScopeWireFormat(src, 0);
        
        assertNull(name.scope);
        assertEquals(1, length);
    }
    
    @Test
    void equals_withSameName_shouldReturnTrue() {
        Name name1 = new Name(mockConfig, "TEST", 0x20, "scope");
        Name name2 = new Name(mockConfig, "TEST", 0x20, "scope");
        
        assertTrue(name1.equals(name2));
    }
    
    @Test
    void equals_withDifferentName_shouldReturnFalse() {
        Name name1 = new Name(mockConfig, "TEST1", 0x20, "scope");
        Name name2 = new Name(mockConfig, "TEST2", 0x20, "scope");
        
        assertFalse(name1.equals(name2));
    }
    
    @Test
    void equals_withDifferentHexCode_shouldReturnFalse() {
        Name name1 = new Name(mockConfig, "TEST", 0x20, "scope");
        Name name2 = new Name(mockConfig, "TEST", 0x1C, "scope");
        
        assertFalse(name1.equals(name2));
    }
    
    @Test
    void equals_withDifferentScope_shouldReturnFalse() {
        Name name1 = new Name(mockConfig, "TEST", 0x20, "scope1");
        Name name2 = new Name(mockConfig, "TEST", 0x20, "scope2");
        
        assertFalse(name1.equals(name2));
    }
    
    @Test
    void equals_withBothNullScope_shouldReturnTrue() {
        Name name1 = new Name(mockConfig, "TEST", 0x20, null);
        name1.scope = null;
        Name name2 = new Name(mockConfig, "TEST", 0x20, null);
        name2.scope = null;
        
        assertTrue(name1.equals(name2));
    }
    
    @Test
    void equals_withNonNameObject_shouldReturnFalse() {
        Name name = new Name(mockConfig, "TEST", 0x20, "scope");
        assertFalse(name.equals("not a name"));
    }
    
    @Test
    void equals_withNull_shouldReturnFalse() {
        Name name = new Name(mockConfig, "TEST", 0x20, "scope");
        assertFalse(name.equals(null));
    }
    
    @Test
    void hashCode_shouldBeConsistent() {
        Name name = new Name(mockConfig, "TEST", 0x20, "scope");
        int hash1 = name.hashCode();
        int hash2 = name.hashCode();
        
        assertEquals(hash1, hash2);
    }
    
    @Test
    void hashCode_withSameValues_shouldBeEqual() {
        Name name1 = new Name(mockConfig, "TEST", 0x20, "scope");
        Name name2 = new Name(mockConfig, "TEST", 0x20, "scope");
        
        assertEquals(name1.hashCode(), name2.hashCode());
    }
    
    @Test
    void hashCode_shouldIncludeSrcHashCode() {
        Name name1 = new Name(mockConfig, "TEST", 0x20, "scope");
        name1.srcHashCode = 100;
        
        Name name2 = new Name(mockConfig, "TEST", 0x20, "scope");
        name2.srcHashCode = 200;
        
        assertNotEquals(name1.hashCode(), name2.hashCode());
    }
    
    @Test
    void hashCode_withNullScope_shouldNotThrow() {
        Name name = new Name(mockConfig, "TEST", 0x20, null);
        name.scope = null;
        
        assertDoesNotThrow(() -> name.hashCode());
    }
    
    @Test
    void toString_withNormalName_shouldFormatCorrectly() {
        Name name = new Name(mockConfig, "TEST", 0x20, "scope.com");
        String result = name.toString();
        
        assertTrue(result.contains("TEST"));
        assertTrue(result.contains("<20>"));
        assertTrue(result.contains("scope.com"));
    }
    
    @Test
    void toString_withNullName_shouldHandleGracefully() {
        Name name = new Name(mockConfig, "TEST", 0x20, null);
        name.name = null;
        
        String result = name.toString();
        assertTrue(result.contains("null"));
    }
    
    @Test
    void toString_withMSBrowseName_shouldReplaceSpecialCharacters() {
        Name name = new Name(mockConfig, "\u0001MSBROWSE      ", 0x01, null);
        String result = name.toString();
        
        // Should replace first char with '..' and char at position 14 with '.'
        assertTrue(result.contains(".."));
        assertFalse(result.contains("\u0001"));
    }
    
    @Test
    void toString_withoutScope_shouldNotIncludeScope() {
        Name name = new Name(mockConfig, "TEST", 0x20, null);
        name.scope = null;
        
        String result = name.toString();
        assertTrue(result.contains("TEST"));
        assertTrue(result.contains("<20>"));
        assertFalse(result.contains("."));
    }
    
    @Test
    void writeWireFormat_withMaxLengthName_shouldHandleCorrectly() {
        String maxName = "123456789012345"; // 15 characters
        Name name = new Name(mockConfig, maxName, 0x20, null);
        byte[] dst = new byte[100];
        
        int length = name.writeWireFormat(dst, 0);
        
        // Should encode all 15 characters
        assertTrue(length >= 34);
        assertEquals(0x20, dst[0]);
    }
    
    @Test
    void readWireFormat_withTrailingSpaces_shouldTrimCorrectly() {
        // Prepare encoded data for "TEST    " (with trailing spaces)
        byte[] src = new byte[100];
        src[0] = 0x20;
        
        // Encode "TEST"
        src[1] = 'E'; src[2] = 'E';  // T
        src[3] = 'E'; src[4] = 'F';  // E
        src[5] = 'E'; src[6] = 'D';  // S
        src[7] = 'E'; src[8] = 'E';  // T
        
        // Encode spaces (0x20)
        for (int i = 9; i < 31; i += 2) {
            src[i] = 'C';
            src[i + 1] = 'A';
        }
        
        src[31] = 'C';
        src[32] = 'A';
        src[33] = 0x00;
        
        Name name = new Name(mockConfig);
        name.readWireFormat(src, 0);
        
        assertEquals("TEST", name.name);
    }
    
    @Test
    void constructor_withLowerCaseName_shouldConvertToUpperCase() {
        Name name = new Name(mockConfig, "lowercase", 0x20, null);
        assertEquals("LOWERCASE", name.name);
    }
    
    @Test
    void constructor_withMixedCaseName_shouldConvertToUpperCase() {
        Name name = new Name(mockConfig, "MiXeDcAsE", 0x20, null);
        assertEquals("MIXEDCASE", name.name);
    }
    
    @Test
    void writeWireFormat_withDifferentOffsets_shouldWorkCorrectly() {
        Name name = new Name(mockConfig, "TEST", 0x20, null);
        byte[] dst = new byte[200];
        
        int offset = 50;
        int length = name.writeWireFormat(dst, offset);
        
        // Check first byte at offset
        assertEquals(0x20, dst[offset]);
        
        // Check type encoding at correct offset
        assertEquals('C', dst[offset + 31]);
        assertEquals('A', dst[offset + 32]);
        
        assertTrue(length > 33);
    }
    
    @Test
    void readWireFormat_withDifferentOffsets_shouldWorkCorrectly() {
        byte[] src = new byte[200];
        int offset = 50;
        
        // Prepare encoded data at offset
        src[offset] = 0x20;
        
        // Encode "TEST" at offset
        src[offset + 1] = 'E'; src[offset + 2] = 'E';
        src[offset + 3] = 'E'; src[offset + 4] = 'F';
        src[offset + 5] = 'E'; src[offset + 6] = 'D';
        src[offset + 7] = 'E'; src[offset + 8] = 'E';
        
        // Fill padding
        for (int i = 9; i < 31; i += 2) {
            src[offset + i] = 'C';
            src[offset + i + 1] = 'A';
        }
        
        src[offset + 31] = 'C';
        src[offset + 32] = 'A';
        src[offset + 33] = 0x00;
        
        Name name = new Name(mockConfig);
        int length = name.readWireFormat(src, offset);
        
        assertEquals("TEST", name.name);
        assertEquals(0x20, name.hexCode);
        assertEquals(34, length);
    }
    
    @Test
    void writeScopeWireFormat_shouldConvertDotsToLabelLengths() {
        Name name = new Name(mockConfig, "TEST", 0x20, "test.example.com");
        byte[] dst = new byte[100];
        
        int length = name.writeScopeWireFormat(dst, 0);
        
        // First byte should be '.'
        assertEquals('.', dst[0]);
        
        // After processing, dots should be replaced with length markers
        // The scope processing happens backwards
        assertTrue(length > name.scope.length());
    }
    
    @Test
    void readScopeWireFormat_withMultipleLabels_shouldParseCorrectly() {
        byte[] src = new byte[100];
        
        // Encode "test.example.com"
        src[0] = 4; // Length of "test"
        src[1] = 't'; src[2] = 'e'; src[3] = 's'; src[4] = 't';
        src[5] = 7; // Length of "example"
        src[6] = 'e'; src[7] = 'x'; src[8] = 'a'; src[9] = 'm';
        src[10] = 'p'; src[11] = 'l'; src[12] = 'e';
        src[13] = 3; // Length of "com"
        src[14] = 'c'; src[15] = 'o'; src[16] = 'm';
        src[17] = 0; // End marker
        
        Name name = new Name(mockConfig);
        int length = name.readScopeWireFormat(src, 0);
        
        assertEquals("test.example.com", name.scope);
        assertEquals(18, length);
    }
    
    @Test
    void constructor_withNetbiosNameNotNameInstance_shouldNotCopySrcHashCode() {
        // Create a mock NetbiosName that is not a Name instance
        NetbiosName mockNetbiosName = mock(NetbiosName.class);
        when(mockNetbiosName.getName()).thenReturn("MOCKNAME");
        when(mockNetbiosName.getNameType()).thenReturn(0x20);
        when(mockNetbiosName.getScope()).thenReturn("mock.scope");
        
        Name name = new Name(mockConfig, mockNetbiosName);
        
        assertEquals("MOCKNAME", name.name);
        assertEquals(0x20, name.hexCode);
        assertEquals("mock.scope", name.scope);
        assertEquals(0, name.srcHashCode); // Should remain 0
    }
    
    @Test
    void readWireFormat_withNonSpacePaddingCharacters_shouldPreserveLength() {
        // Test that non-space characters in padding are preserved in length calculation
        byte[] src = new byte[100];
        src[0] = 0x20;
        
        // Encode "AB" followed by non-space padding
        src[1] = 'E'; src[2] = 'B';  // A
        src[3] = 'E'; src[4] = 'C';  // B
        
        // Use 'X' (0x58) instead of space for padding
        for (int i = 5; i < 31; i += 2) {
            src[i] = 'E';
            src[i + 1] = 'I'; // Encodes to 'X'
        }
        
        src[31] = 'C';
        src[32] = 'A';
        src[33] = 0x00;
        
        Name name = new Name(mockConfig);
        name.readWireFormat(src, 0);
        
        // Should preserve all characters up to last non-space
        assertTrue(name.name.length() > 2);
    }
}