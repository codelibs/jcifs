package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for Trans2QueryPathInformationResponse
 */
class Trans2QueryPathInformationResponseTest {

    private Trans2QueryPathInformationResponse response;

    @BeforeEach
    void setUp() {
        response = new Trans2QueryPathInformationResponse(Trans2QueryPathInformationResponse.SMB_QUERY_FILE_BASIC_INFO);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should initialize with SMB_QUERY_FILE_BASIC_INFO level")
        void testConstructorWithBasicInfo() throws Exception {
            Trans2QueryPathInformationResponse resp =
                    new Trans2QueryPathInformationResponse(Trans2QueryPathInformationResponse.SMB_QUERY_FILE_BASIC_INFO);

            // Use reflection to verify the information level
            Field infoLevel = Trans2QueryPathInformationResponse.class.getDeclaredField("informationLevel");
            infoLevel.setAccessible(true);
            assertEquals(Trans2QueryPathInformationResponse.SMB_QUERY_FILE_BASIC_INFO, infoLevel.getInt(resp));

            // Verify subCommand is set correctly
            Field subCmd = SmbComTransactionResponse.class.getDeclaredField("subCommand");
            subCmd.setAccessible(true);
            assertEquals(SmbComTransaction.TRANS2_QUERY_PATH_INFORMATION, subCmd.getInt(resp));
        }

        @Test
        @DisplayName("Should initialize with SMB_QUERY_FILE_STANDARD_INFO level")
        void testConstructorWithStandardInfo() throws Exception {
            Trans2QueryPathInformationResponse resp =
                    new Trans2QueryPathInformationResponse(Trans2QueryPathInformationResponse.SMB_QUERY_FILE_STANDARD_INFO);

            Field infoLevel = Trans2QueryPathInformationResponse.class.getDeclaredField("informationLevel");
            infoLevel.setAccessible(true);
            assertEquals(Trans2QueryPathInformationResponse.SMB_QUERY_FILE_STANDARD_INFO, infoLevel.getInt(resp));
        }

        @Test
        @DisplayName("Should initialize with custom information level")
        void testConstructorWithCustomLevel() throws Exception {
            int customLevel = 0x200;
            Trans2QueryPathInformationResponse resp = new Trans2QueryPathInformationResponse(customLevel);

            Field infoLevel = Trans2QueryPathInformationResponse.class.getDeclaredField("informationLevel");
            infoLevel.setAccessible(true);
            assertEquals(customLevel, infoLevel.getInt(resp));
        }
    }

    @Nested
    @DisplayName("Wire Format Tests")
    class WireFormatTests {

        @Test
        @DisplayName("Should read parameters wire format")
        void testReadParametersWireFormat() {
            byte[] buffer = new byte[10];
            int result = response.readParametersWireFormat(buffer, 0, 2);
            assertEquals(2, result);
        }

        @Test
        @DisplayName("Should write setup wire format")
        void testWriteSetupWireFormat() {
            byte[] buffer = new byte[100];
            int result = response.writeSetupWireFormat(buffer, 0);
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should write parameters wire format")
        void testWriteParametersWireFormat() {
            byte[] buffer = new byte[100];
            int result = response.writeParametersWireFormat(buffer, 0);
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should write data wire format")
        void testWriteDataWireFormat() {
            byte[] buffer = new byte[100];
            int result = response.writeDataWireFormat(buffer, 0);
            assertEquals(0, result);
        }
    }

    @Nested
    @DisplayName("SmbQueryFileBasicInfo Tests")
    class SmbQueryFileBasicInfoTests {

        @Test
        @DisplayName("Should create and access basic info")
        void testBasicInfoCreation() {
            Trans2QueryPathInformationResponse.SmbQueryFileBasicInfo basicInfo = response.new SmbQueryFileBasicInfo();

            assertNotNull(basicInfo);
            assertEquals(0L, basicInfo.getCreateTime());
            assertEquals(0L, basicInfo.getLastWriteTime());
            assertEquals(0L, basicInfo.getSize());
            assertEquals(0, basicInfo.getAttributes());
        }

        @Test
        @DisplayName("Should set and get basic info attributes")
        void testBasicInfoAttributes() {
            Trans2QueryPathInformationResponse.SmbQueryFileBasicInfo basicInfo = response.new SmbQueryFileBasicInfo();

            basicInfo.attributes = 0x20; // Archive attribute
            basicInfo.createTime = 1000000L;
            basicInfo.lastWriteTime = 2000000L;
            basicInfo.lastAccessTime = 1500000L;
            basicInfo.changeTime = 2500000L;

            assertEquals(0x20, basicInfo.getAttributes());
            assertEquals(1000000L, basicInfo.getCreateTime());
            assertEquals(2000000L, basicInfo.getLastWriteTime());
            assertEquals(0L, basicInfo.getSize()); // Basic info always returns 0 for size
        }

        @Test
        @DisplayName("Should generate correct toString for basic info")
        void testBasicInfoToString() {
            Trans2QueryPathInformationResponse.SmbQueryFileBasicInfo basicInfo = response.new SmbQueryFileBasicInfo();

            basicInfo.attributes = 0x20;
            String str = basicInfo.toString();

            assertNotNull(str);
            assertTrue(str.contains("SmbQueryFileBasicInfo"));
            assertTrue(str.contains("attributes=0x"));
        }
    }

    @Nested
    @DisplayName("SmbQueryFileStandardInfo Tests")
    class SmbQueryFileStandardInfoTests {

        @Test
        @DisplayName("Should create and access standard info")
        void testStandardInfoCreation() {
            Trans2QueryPathInformationResponse.SmbQueryFileStandardInfo standardInfo = response.new SmbQueryFileStandardInfo();

            assertNotNull(standardInfo);
            assertEquals(0L, standardInfo.getCreateTime());
            assertEquals(0L, standardInfo.getLastWriteTime());
            assertEquals(0L, standardInfo.getSize());
            assertEquals(0, standardInfo.getAttributes());
        }

        @Test
        @DisplayName("Should set and get standard info attributes")
        void testStandardInfoAttributes() {
            Trans2QueryPathInformationResponse.SmbQueryFileStandardInfo standardInfo = response.new SmbQueryFileStandardInfo();

            standardInfo.allocationSize = 4096L;
            standardInfo.endOfFile = 2048L;
            standardInfo.numberOfLinks = 1;
            standardInfo.deletePending = false;
            standardInfo.directory = false;

            assertEquals(2048L, standardInfo.getSize()); // Size returns endOfFile
            assertEquals(0, standardInfo.getAttributes()); // Standard info always returns 0 for attributes
            assertFalse(standardInfo.deletePending);
            assertFalse(standardInfo.directory);
        }

        @Test
        @DisplayName("Should handle directory flag")
        void testStandardInfoDirectory() {
            Trans2QueryPathInformationResponse.SmbQueryFileStandardInfo standardInfo = response.new SmbQueryFileStandardInfo();

            standardInfo.directory = true;
            assertTrue(standardInfo.directory);
        }

        @Test
        @DisplayName("Should generate correct toString for standard info")
        void testStandardInfoToString() {
            Trans2QueryPathInformationResponse.SmbQueryFileStandardInfo standardInfo = response.new SmbQueryFileStandardInfo();

            standardInfo.allocationSize = 4096L;
            standardInfo.endOfFile = 2048L;
            standardInfo.numberOfLinks = 1;

            String str = standardInfo.toString();

            assertNotNull(str);
            assertTrue(str.contains("SmbQueryInfoStandard"));
            assertTrue(str.contains("allocationSize=4096"));
            assertTrue(str.contains("endOfFile=2048"));
        }
    }

    @Nested
    @DisplayName("Data Reading Tests")
    class DataReadingTests {

        @Test
        @DisplayName("Should read data for basic info level")
        void testReadDataBasicInfo() {
            Trans2QueryPathInformationResponse resp =
                    new Trans2QueryPathInformationResponse(Trans2QueryPathInformationResponse.SMB_QUERY_FILE_BASIC_INFO);

            // Create a buffer with sample data
            byte[] buffer = new byte[100];
            // Fill with some test data
            for (int i = 0; i < buffer.length; i++) {
                buffer[i] = (byte) (i % 256);
            }

            int result = resp.readDataWireFormat(buffer, 0, 40);
            assertNotNull(resp.info);
            assertTrue(resp.info instanceof Trans2QueryPathInformationResponse.SmbQueryFileBasicInfo);
        }

        @Test
        @DisplayName("Should read data for standard info level")
        void testReadDataStandardInfo() {
            Trans2QueryPathInformationResponse resp =
                    new Trans2QueryPathInformationResponse(Trans2QueryPathInformationResponse.SMB_QUERY_FILE_STANDARD_INFO);

            // Create a buffer with sample data
            byte[] buffer = new byte[100];

            int result = resp.readDataWireFormat(buffer, 0, 24);
            assertNotNull(resp.info);
            assertTrue(resp.info instanceof Trans2QueryPathInformationResponse.SmbQueryFileStandardInfo);
        }

        @Test
        @DisplayName("Should return 0 for unknown information level")
        void testReadDataUnknownLevel() {
            Trans2QueryPathInformationResponse resp = new Trans2QueryPathInformationResponse(0x999);

            byte[] buffer = new byte[100];
            int result = resp.readDataWireFormat(buffer, 0, 50);
            assertEquals(0, result);
            assertNull(resp.info);
        }
    }

    @Nested
    @DisplayName("Mock Interaction Tests")
    class MockInteractionTests {

        @Test
        @DisplayName("Should interact with mock Info interface")
        void testMockInfoInteraction() {
            // Create a mock of the Info interface
            Info mockInfo = mock(Info.class);

            // Set up mock behavior
            when(mockInfo.getAttributes()).thenReturn(0x20);
            when(mockInfo.getSize()).thenReturn(1024L);
            when(mockInfo.getCreateTime()).thenReturn(1000000L);
            when(mockInfo.getLastWriteTime()).thenReturn(2000000L);

            // Use the mock
            response.info = mockInfo;

            // Verify interactions
            assertEquals(0x20, response.info.getAttributes());
            assertEquals(1024L, response.info.getSize());
            assertEquals(1000000L, response.info.getCreateTime());
            assertEquals(2000000L, response.info.getLastWriteTime());

            // Verify the mock was called
            verify(mockInfo).getAttributes();
            verify(mockInfo).getSize();
            verify(mockInfo).getCreateTime();
            verify(mockInfo).getLastWriteTime();
        }
    }
}