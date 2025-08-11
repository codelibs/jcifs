package jcifs.internal.smb1.trans2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.config.PropertyConfiguration;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;

import java.util.Properties;

class Trans2FindNext2Test {

    private Trans2FindNext2 trans2FindNext2;
    private Configuration config;
    
    @Mock
    private Configuration mockConfig;
    
    private static final int TEST_SID = 0x1234;
    private static final int TEST_RESUME_KEY = 0xABCD;
    private static final String TEST_FILENAME = "testfile.txt";
    private static final int TEST_BATCH_COUNT = 100;
    private static final int TEST_BATCH_SIZE = 8192;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        Properties props = new Properties();
        config = new PropertyConfiguration(props);
    }

    @Test
    void testConstructor() {
        // Test constructor initializes all fields correctly
        trans2FindNext2 = new Trans2FindNext2(config, TEST_SID, TEST_RESUME_KEY, 
                                              TEST_FILENAME, TEST_BATCH_COUNT, TEST_BATCH_SIZE);
        
        assertNotNull(trans2FindNext2);
        assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION2, trans2FindNext2.getCommand());
        assertEquals(SmbComTransaction.TRANS2_FIND_NEXT2, trans2FindNext2.getSubCommand());
        // maxParameterCount, maxDataCount, and maxSetupCount are protected fields
        // Their values are verified through the wire format methods
    }

    @Test
    void testReset() {
        // Test reset method updates resumeKey and filename
        trans2FindNext2 = new Trans2FindNext2(config, TEST_SID, TEST_RESUME_KEY, 
                                              TEST_FILENAME, TEST_BATCH_COUNT, TEST_BATCH_SIZE);
        
        int newResumeKey = 0x5678;
        String newFilename = "newfile.txt";
        
        trans2FindNext2.reset(newResumeKey, newFilename);
        
        // Verify by writing parameters and checking the buffer
        byte[] buffer = new byte[256];
        int written = trans2FindNext2.writeParametersWireFormat(buffer, 0);
        
        // Check resume key at offset 6 (after sid and maxItems and informationLevel)
        int actualResumeKey = SMBUtil.readInt4(buffer, 6);
        assertEquals(newResumeKey, actualResumeKey);
        
        // Check filename is updated (it's at the end after flags)
        String actualFilename = readString(buffer, 12, written - 12);
        assertEquals(newFilename, actualFilename);
    }

    @Test
    void testWriteSetupWireFormat() {
        // Test setup wire format writing
        trans2FindNext2 = new Trans2FindNext2(config, TEST_SID, TEST_RESUME_KEY, 
                                              TEST_FILENAME, TEST_BATCH_COUNT, TEST_BATCH_SIZE);
        
        byte[] buffer = new byte[10];
        int written = trans2FindNext2.writeSetupWireFormat(buffer, 0);
        
        assertEquals(2, written);
        assertEquals(SmbComTransaction.TRANS2_FIND_NEXT2, buffer[0]);
        assertEquals(0x00, buffer[1]);
    }

    @Test
    void testWriteParametersWireFormat() {
        // Test parameters wire format writing
        trans2FindNext2 = new Trans2FindNext2(config, TEST_SID, TEST_RESUME_KEY, 
                                              TEST_FILENAME, TEST_BATCH_COUNT, TEST_BATCH_SIZE);
        
        byte[] buffer = new byte[256];
        int written = trans2FindNext2.writeParametersWireFormat(buffer, 0);
        
        // Verify sid (2 bytes)
        assertEquals(TEST_SID, SMBUtil.readInt2(buffer, 0));
        
        // Verify maxItems (2 bytes)
        assertEquals(TEST_BATCH_COUNT, SMBUtil.readInt2(buffer, 2));
        
        // Verify informationLevel (2 bytes) - should be SMB_FILE_BOTH_DIRECTORY_INFO (0x104)
        assertEquals(Trans2FindFirst2.SMB_FILE_BOTH_DIRECTORY_INFO, SMBUtil.readInt2(buffer, 4));
        
        // Verify resumeKey (4 bytes)
        assertEquals(TEST_RESUME_KEY, SMBUtil.readInt4(buffer, 6));
        
        // Verify tflags (2 bytes) - should be 0x00
        assertEquals(0x00, SMBUtil.readInt2(buffer, 10));
        
        // Verify filename
        String actualFilename = readString(buffer, 12, written - 12);
        assertEquals(TEST_FILENAME, actualFilename);
        
        // Verify total bytes written
        assertTrue(written >= 12 + TEST_FILENAME.length());
    }

    @Test
    void testWriteDataWireFormat() {
        // Test data wire format writing (should return 0)
        trans2FindNext2 = new Trans2FindNext2(config, TEST_SID, TEST_RESUME_KEY, 
                                              TEST_FILENAME, TEST_BATCH_COUNT, TEST_BATCH_SIZE);
        
        byte[] buffer = new byte[10];
        int written = trans2FindNext2.writeDataWireFormat(buffer, 0);
        
        assertEquals(0, written);
    }

    @Test
    void testReadSetupWireFormat() {
        // Test setup wire format reading (should return 0)
        trans2FindNext2 = new Trans2FindNext2(config, TEST_SID, TEST_RESUME_KEY, 
                                              TEST_FILENAME, TEST_BATCH_COUNT, TEST_BATCH_SIZE);
        
        byte[] buffer = new byte[10];
        int read = trans2FindNext2.readSetupWireFormat(buffer, 0, 10);
        
        assertEquals(0, read);
    }

    @Test
    void testReadParametersWireFormat() {
        // Test parameters wire format reading (should return 0)
        trans2FindNext2 = new Trans2FindNext2(config, TEST_SID, TEST_RESUME_KEY, 
                                              TEST_FILENAME, TEST_BATCH_COUNT, TEST_BATCH_SIZE);
        
        byte[] buffer = new byte[10];
        int read = trans2FindNext2.readParametersWireFormat(buffer, 0, 10);
        
        assertEquals(0, read);
    }

    @Test
    void testReadDataWireFormat() {
        // Test data wire format reading (should return 0)
        trans2FindNext2 = new Trans2FindNext2(config, TEST_SID, TEST_RESUME_KEY, 
                                              TEST_FILENAME, TEST_BATCH_COUNT, TEST_BATCH_SIZE);
        
        byte[] buffer = new byte[10];
        int read = trans2FindNext2.readDataWireFormat(buffer, 0, 10);
        
        assertEquals(0, read);
    }

    @Test
    void testToString() {
        // Test toString method
        when(mockConfig.getListSize()).thenReturn(50);
        
        trans2FindNext2 = new Trans2FindNext2(mockConfig, TEST_SID, TEST_RESUME_KEY, 
                                              TEST_FILENAME, TEST_BATCH_COUNT, TEST_BATCH_SIZE);
        
        String result = trans2FindNext2.toString();
        
        assertNotNull(result);
        assertTrue(result.contains("Trans2FindNext2"));
        assertTrue(result.contains("sid=" + TEST_SID));
        assertTrue(result.contains("searchCount=50"));
        assertTrue(result.contains("informationLevel=0x"));
        assertTrue(result.contains("resumeKey=0x" + Hexdump.toHexString(TEST_RESUME_KEY, 4)));
        assertTrue(result.contains("flags=0x00"));
        assertTrue(result.contains("filename=" + TEST_FILENAME));
    }

    @ParameterizedTest
    @CsvSource({
        "0, 0, '', 10, 1024",
        "65535, 65535, 'file.txt', 1, 1",
        "1, 1, 'longfilename_with_many_characters.txt', 1000, 65535",
        "32768, 16384, 'test*.txt', 500, 32768"
    })
    void testConstructorWithVariousParameters(int sid, int resumeKey, String filename, 
                                             int batchCount, int batchSize) {
        // Test constructor with various parameter combinations
        trans2FindNext2 = new Trans2FindNext2(config, sid, resumeKey, 
                                              filename, batchCount, batchSize);
        
        assertNotNull(trans2FindNext2);
        
        // Verify parameters are written correctly
        byte[] buffer = new byte[512];
        int written = trans2FindNext2.writeParametersWireFormat(buffer, 0);
        
        assertEquals(sid, SMBUtil.readInt2(buffer, 0));
        assertEquals(batchCount, SMBUtil.readInt2(buffer, 2));
        assertEquals(resumeKey, SMBUtil.readInt4(buffer, 6));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "",
        "a",
        "test.txt",
        "very_long_filename_that_exceeds_normal_length_limits_and_tests_buffer_handling.txt",
        "file with spaces.txt",
        "file*with?wildcards.txt",
        "../relative/path/file.txt",
        "C:\\absolute\\path\\file.txt"
    })
    void testFilenameHandling(String filename) {
        // Test various filename formats
        trans2FindNext2 = new Trans2FindNext2(config, TEST_SID, TEST_RESUME_KEY, 
                                              filename, TEST_BATCH_COUNT, TEST_BATCH_SIZE);
        
        byte[] buffer = new byte[1024];
        int written = trans2FindNext2.writeParametersWireFormat(buffer, 0);
        
        // Verify filename is written and can be read back
        String actualFilename = readString(buffer, 12, written - 12);
        assertEquals(filename, actualFilename);
    }

    @Test
    void testResetMultipleTimes() {
        // Test multiple resets to ensure state is properly maintained
        trans2FindNext2 = new Trans2FindNext2(config, TEST_SID, TEST_RESUME_KEY, 
                                              TEST_FILENAME, TEST_BATCH_COUNT, TEST_BATCH_SIZE);
        
        for (int i = 1; i <= 5; i++) {
            int newResumeKey = i * 1000;
            String newFilename = "file" + i + ".txt";
            
            trans2FindNext2.reset(newResumeKey, newFilename);
            
            byte[] buffer = new byte[256];
            int written = trans2FindNext2.writeParametersWireFormat(buffer, 0);
            
            assertEquals(newResumeKey, SMBUtil.readInt4(buffer, 6));
            String actualFilename = readString(buffer, 12, written - 12);
            assertEquals(newFilename, actualFilename);
        }
    }

    @Test
    void testLargeBatchParameters() {
        // Test with maximum allowed values
        int maxSid = 0xFFFF;
        int maxResumeKey = 0x7FFFFFFF;
        int maxBatchCount = 65535;
        int maxBatchSize = 65535;
        
        trans2FindNext2 = new Trans2FindNext2(config, maxSid, maxResumeKey, 
                                              TEST_FILENAME, maxBatchCount, maxBatchSize);
        
        byte[] buffer = new byte[512];
        int written = trans2FindNext2.writeParametersWireFormat(buffer, 0);
        
        assertEquals(maxSid, SMBUtil.readInt2(buffer, 0));
        assertEquals(maxBatchCount, SMBUtil.readInt2(buffer, 2));
        assertEquals(maxResumeKey, SMBUtil.readInt4(buffer, 6));
        // maxBatchSize is stored in the protected field maxDataCount
    }

    @Test
    void testEmptyFilenameHandling() {
        // Test with empty filename
        trans2FindNext2 = new Trans2FindNext2(config, TEST_SID, TEST_RESUME_KEY, 
                                              "", TEST_BATCH_COUNT, TEST_BATCH_SIZE);
        
        byte[] buffer = new byte[256];
        int written = trans2FindNext2.writeParametersWireFormat(buffer, 0);
        
        // Should still write the parameters correctly
        assertEquals(TEST_SID, SMBUtil.readInt2(buffer, 0));
        assertEquals(TEST_BATCH_COUNT, SMBUtil.readInt2(buffer, 2));
        assertEquals(TEST_RESUME_KEY, SMBUtil.readInt4(buffer, 6));
        
        // Empty filename should result in minimal bytes written
        assertTrue(written >= 12); // At least the fixed parameters
    }

    @Test
    void testInformationLevelConstant() {
        // Verify the information level is set correctly
        trans2FindNext2 = new Trans2FindNext2(config, TEST_SID, TEST_RESUME_KEY, 
                                              TEST_FILENAME, TEST_BATCH_COUNT, TEST_BATCH_SIZE);
        
        byte[] buffer = new byte[256];
        trans2FindNext2.writeParametersWireFormat(buffer, 0);
        
        // Information level should be SMB_FILE_BOTH_DIRECTORY_INFO (0x104)
        int informationLevel = SMBUtil.readInt2(buffer, 4);
        assertEquals(Trans2FindFirst2.SMB_FILE_BOTH_DIRECTORY_INFO, informationLevel);
    }

    @Test
    void testZeroValues() {
        // Test with zero values for numeric parameters
        trans2FindNext2 = new Trans2FindNext2(config, 0, 0, "", 0, 0);
        
        assertNotNull(trans2FindNext2);
        
        byte[] buffer = new byte[256];
        int written = trans2FindNext2.writeParametersWireFormat(buffer, 0);
        
        assertEquals(0, SMBUtil.readInt2(buffer, 0)); // sid
        assertEquals(0, SMBUtil.readInt2(buffer, 2)); // maxItems
        assertEquals(0, SMBUtil.readInt4(buffer, 6)); // resumeKey
    }

    // Helper method to read string from buffer
    private String readString(byte[] buffer, int offset, int maxLength) {
        int length = 0;
        for (int i = offset; i < offset + maxLength && i < buffer.length; i++) {
            if (buffer[i] == 0) {
                break;
            }
            length++;
        }
        return new String(buffer, offset, length);
    }
}
