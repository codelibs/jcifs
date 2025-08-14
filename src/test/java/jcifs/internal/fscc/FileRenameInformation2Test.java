package jcifs.internal.fscc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for FileRenameInformation2
 */
@DisplayName("FileRenameInformation2 Tests")
class FileRenameInformation2Test {

    private FileRenameInformation2 fileRenameInfo;

    @BeforeEach
    void setUp() {
        fileRenameInfo = new FileRenameInformation2();
    }

    @Test
    @DisplayName("Test default constructor")
    void testDefaultConstructor() {
        assertNotNull(fileRenameInfo);
    }

    @Test
    @DisplayName("Test parameterized constructor")
    void testParameterizedConstructor() {
        String fileName = "test.txt";
        boolean replaceIfExists = true;

        FileRenameInformation2 info = new FileRenameInformation2(fileName, replaceIfExists);

        assertNotNull(info);
    }

    @Test
    @DisplayName("Test getFileInformationLevel returns correct value")
    void testGetFileInformationLevel() {
        assertEquals(FileInformation.FILE_RENAME_INFO, fileRenameInfo.getFileInformationLevel());
    }

    @Test
    @DisplayName("Test size calculation with short filename")
    void testSizeWithShortFilename() {
        FileRenameInformation2 info = new FileRenameInformation2("test.txt", false);
        // 20 bytes fixed + 2 * 8 chars = 20 + 16 = 36
        assertEquals(36, info.size());
    }

    @Test
    @DisplayName("Test size calculation with long filename")
    void testSizeWithLongFilename() {
        String longFileName = "verylongfilename_with_many_characters.txt";
        FileRenameInformation2 info = new FileRenameInformation2(longFileName, false);
        // 20 bytes fixed + 2 * length
        assertEquals(20 + 2 * longFileName.length(), info.size());
    }

    @Test
    @DisplayName("Test size calculation with empty filename")
    void testSizeWithEmptyFilename() {
        FileRenameInformation2 info = new FileRenameInformation2("", false);
        assertEquals(20, info.size());
    }

    @Test
    @DisplayName("Test encode with replaceIfExists true")
    void testEncodeWithReplaceIfExistsTrue() {
        String fileName = "newfile.txt";
        FileRenameInformation2 info = new FileRenameInformation2(fileName, true);

        byte[] buffer = new byte[100];
        int bytesWritten = info.encode(buffer, 0);

        // Verify replaceIfExists flag
        assertEquals(1, buffer[0]);

        // Verify file name length
        int nameLength = SMBUtil.readInt4(buffer, 16);
        assertEquals(fileName.getBytes(StandardCharsets.UTF_16LE).length, nameLength);

        // Verify file name
        byte[] nameBytes = new byte[nameLength];
        System.arraycopy(buffer, 20, nameBytes, 0, nameLength);
        String decodedName = new String(nameBytes, StandardCharsets.UTF_16LE);
        assertEquals(fileName, decodedName);

        // Verify bytes written
        assertEquals(20 + nameLength, bytesWritten);
    }

    @Test
    @DisplayName("Test encode with replaceIfExists false")
    void testEncodeWithReplaceIfExistsFalse() {
        String fileName = "newfile.txt";
        FileRenameInformation2 info = new FileRenameInformation2(fileName, false);

        byte[] buffer = new byte[100];
        int bytesWritten = info.encode(buffer, 0);

        // Verify replaceIfExists flag
        assertEquals(0, buffer[0]);

        // Verify file name length
        int nameLength = SMBUtil.readInt4(buffer, 16);
        assertEquals(fileName.getBytes(StandardCharsets.UTF_16LE).length, nameLength);

        // Verify file name
        byte[] nameBytes = new byte[nameLength];
        System.arraycopy(buffer, 20, nameBytes, 0, nameLength);
        String decodedName = new String(nameBytes, StandardCharsets.UTF_16LE);
        assertEquals(fileName, decodedName);

        // Verify bytes written
        assertEquals(20 + nameLength, bytesWritten);
    }

    @Test
    @DisplayName("Test encode with non-zero destination index")
    void testEncodeWithNonZeroDestIndex() {
        String fileName = "test.txt";
        FileRenameInformation2 info = new FileRenameInformation2(fileName, true);

        byte[] buffer = new byte[100];
        int dstIndex = 10;
        int bytesWritten = info.encode(buffer, dstIndex);

        // Verify replaceIfExists flag at correct position
        assertEquals(1, buffer[dstIndex]);

        // Verify file name length at correct position
        int nameLength = SMBUtil.readInt4(buffer, dstIndex + 16);
        assertEquals(fileName.getBytes(StandardCharsets.UTF_16LE).length, nameLength);

        // Verify bytes written
        assertEquals(20 + nameLength, bytesWritten);
    }

    @Test
    @DisplayName("Test decode with replaceIfExists true")
    void testDecodeWithReplaceIfExistsTrue() throws SMBProtocolDecodingException {
        String originalFileName = "testfile.txt";
        byte[] nameBytes = originalFileName.getBytes(StandardCharsets.UTF_16LE);

        byte[] buffer = new byte[100];
        buffer[0] = 1; // replaceIfExists = true
        // Skip 7 reserved bytes (1-7)
        // Skip 8 bytes for RootDirectory (8-15)
        SMBUtil.writeInt4(nameBytes.length, buffer, 16);
        System.arraycopy(nameBytes, 0, buffer, 20, nameBytes.length);

        FileRenameInformation2 info = new FileRenameInformation2();
        int bytesRead = info.decode(buffer, 0, buffer.length);

        assertEquals(20 + nameBytes.length, bytesRead);
    }

    @Test
    @DisplayName("Test decode with replaceIfExists false")
    void testDecodeWithReplaceIfExistsFalse() throws SMBProtocolDecodingException {
        String originalFileName = "testfile.txt";
        byte[] nameBytes = originalFileName.getBytes(StandardCharsets.UTF_16LE);

        byte[] buffer = new byte[100];
        buffer[0] = 0; // replaceIfExists = false
        // Skip 7 reserved bytes (1-7)
        // Skip 8 bytes for RootDirectory (8-15)
        SMBUtil.writeInt4(nameBytes.length, buffer, 16);
        System.arraycopy(nameBytes, 0, buffer, 20, nameBytes.length);

        FileRenameInformation2 info = new FileRenameInformation2();
        int bytesRead = info.decode(buffer, 0, buffer.length);

        assertEquals(20 + nameBytes.length, bytesRead);
    }

    @Test
    @DisplayName("Test decode with non-zero buffer index")
    void testDecodeWithNonZeroBufferIndex() throws SMBProtocolDecodingException {
        String originalFileName = "file.txt";
        byte[] nameBytes = originalFileName.getBytes(StandardCharsets.UTF_16LE);

        byte[] buffer = new byte[100];
        int startIndex = 10;
        buffer[startIndex] = 1; // replaceIfExists = true
        SMBUtil.writeInt4(nameBytes.length, buffer, startIndex + 16);
        System.arraycopy(nameBytes, 0, buffer, startIndex + 20, nameBytes.length);

        FileRenameInformation2 info = new FileRenameInformation2();
        int bytesRead = info.decode(buffer, startIndex, buffer.length - startIndex);

        assertEquals(20 + nameBytes.length, bytesRead);
    }

    @Test
    @DisplayName("Test encode and decode round trip")
    void testEncodeDecodeRoundTrip() throws SMBProtocolDecodingException {
        String fileName = "roundtrip_test.txt";
        boolean replaceIfExists = true;

        FileRenameInformation2 original = new FileRenameInformation2(fileName, replaceIfExists);

        // Encode
        byte[] buffer = new byte[200];
        int bytesWritten = original.encode(buffer, 0);

        // Decode
        FileRenameInformation2 decoded = new FileRenameInformation2();
        int bytesRead = decoded.decode(buffer, 0, bytesWritten);

        // Verify round trip
        assertEquals(bytesWritten, bytesRead);
        assertEquals(original.size(), decoded.size());
        assertEquals(original.getFileInformationLevel(), decoded.getFileInformationLevel());
    }

    @Test
    @DisplayName("Test with Unicode filename")
    void testWithUnicodeFilename() {
        String unicodeFileName = "文件名.txt";
        FileRenameInformation2 info = new FileRenameInformation2(unicodeFileName, false);

        byte[] buffer = new byte[200];
        int bytesWritten = info.encode(buffer, 0);

        // Verify the encoded data
        int nameLength = SMBUtil.readInt4(buffer, 16);
        byte[] nameBytes = new byte[nameLength];
        System.arraycopy(buffer, 20, nameBytes, 0, nameLength);
        String decodedName = new String(nameBytes, StandardCharsets.UTF_16LE);

        assertEquals(unicodeFileName, decodedName);
        assertEquals(20 + nameLength, bytesWritten);
    }

    @Test
    @DisplayName("Test with special characters in filename")
    void testWithSpecialCharactersInFilename() throws SMBProtocolDecodingException {
        String specialFileName = "file!@#$%^&*().txt";
        FileRenameInformation2 original = new FileRenameInformation2(specialFileName, true);

        byte[] buffer = new byte[200];
        int bytesWritten = original.encode(buffer, 0);

        FileRenameInformation2 decoded = new FileRenameInformation2();
        int bytesRead = decoded.decode(buffer, 0, bytesWritten);

        assertEquals(bytesWritten, bytesRead);
    }

    @Test
    @DisplayName("Test with very long filename")
    void testWithVeryLongFilename() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            sb.append("longname");
        }
        String longFileName = sb.toString() + ".txt";

        FileRenameInformation2 info = new FileRenameInformation2(longFileName, false);

        int expectedSize = 20 + 2 * longFileName.length();
        assertEquals(expectedSize, info.size());

        byte[] buffer = new byte[expectedSize + 100];
        int bytesWritten = info.encode(buffer, 0);

        assertEquals(expectedSize, bytesWritten);
    }

    @Test
    @DisplayName("Test decode with empty filename")
    void testDecodeWithEmptyFilename() throws SMBProtocolDecodingException {
        byte[] buffer = new byte[100];
        buffer[0] = 0; // replaceIfExists = false
        SMBUtil.writeInt4(0, buffer, 16); // name length = 0

        FileRenameInformation2 info = new FileRenameInformation2();
        int bytesRead = info.decode(buffer, 0, buffer.length);

        assertEquals(20, bytesRead);
    }

    @Test
    @DisplayName("Test encode with empty filename")
    void testEncodeWithEmptyFilename() {
        FileRenameInformation2 info = new FileRenameInformation2("", true);

        byte[] buffer = new byte[100];
        int bytesWritten = info.encode(buffer, 0);

        assertEquals(1, buffer[0]); // replaceIfExists = true
        assertEquals(0, SMBUtil.readInt4(buffer, 16)); // name length = 0
        assertEquals(20, bytesWritten);
    }

    @Test
    @DisplayName("Test multiple encode operations")
    void testMultipleEncodeOperations() {
        String fileName = "test.txt";
        FileRenameInformation2 info = new FileRenameInformation2(fileName, true);

        byte[] buffer1 = new byte[100];
        byte[] buffer2 = new byte[100];

        int bytesWritten1 = info.encode(buffer1, 0);
        int bytesWritten2 = info.encode(buffer2, 0);

        assertEquals(bytesWritten1, bytesWritten2);
        assertArrayEquals(buffer1, buffer2);
    }
}
