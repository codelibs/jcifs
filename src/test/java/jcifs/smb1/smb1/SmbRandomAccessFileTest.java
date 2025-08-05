/*
 * Copyright 2024 Shinsuke Ogawa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import jcifs.smb.SmbException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

class SmbRandomAccessFileTest {

  private SmbFile smbFile;
  private SmbRandomAccessFile smbRandomAccessFile;

  @BeforeEach
  void setUp() throws MalformedURLException, SmbException, UnknownHostException {
    // Mock SmbFile and its dependencies
    smbFile = mock(SmbFile.class);
    when(smbFile.isOpen()).thenReturn(true);

    // Mock the transport and session to avoid NullPointerExceptions
    SmbTransport transport = mock(SmbTransport.class);
    when(transport.rcv_buf_size).thenReturn(8192);
    when(transport.snd_buf_size).thenReturn(8192);

    SmbSession session = mock(SmbSession.class);
    when(session.transport).thenReturn(transport);

    SmbTree tree = mock(SmbTree.class);
    when(tree.session).thenReturn(session);
    when(smbFile.tree).thenReturn(tree);

    // Create a new SmbRandomAccessFile instance for each test
    smbRandomAccessFile = new SmbRandomAccessFile(smbFile, "rw");
  }

  @Test
  void testConstructorWithReadMode() throws Exception {
    // Test constructor with "r" mode
    smbRandomAccessFile = new SmbRandomAccessFile(smbFile, "r");
    assertNotNull(smbRandomAccessFile);
  }

  @Test
  void testConstructorWithInvalidMode() {
    // Test constructor with an invalid mode
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new SmbRandomAccessFile(smbFile, "invalid");
        });
  }

  @Test
  void testRead() throws SmbException {
    // Mock the send method to simulate reading a single byte
    doAnswer(
            new Answer<Void>() {
              @Override
              public Void answer(InvocationOnMock invocation) throws Throwable {
                SmbComReadAndXResponse response = invocation.getArgument(1);
                response.dataLength = 1;
                byte[] b = response.b;
                b[response.off] = 65; // 'A'
                return null;
              }
            })
        .when(smbFile)
        .send(any(SmbComReadAndX.class), any(SmbComReadAndXResponse.class));

    // Read a single byte and assert its value
    int result = smbRandomAccessFile.read();
    assertEquals(65, result);
  }

  @Test
  void testReadByteArray() throws SmbException {
    final byte[] testData = "Hello, World!".getBytes();

    // Mock the send method to simulate reading a byte array
    doAnswer(
            new Answer<Void>() {
              @Override
              public Void answer(InvocationOnMock invocation) throws Throwable {
                SmbComReadAndXResponse response = invocation.getArgument(1);
                response.dataLength = testData.length;
                System.arraycopy(testData, 0, response.b, response.off, testData.length);
                return null;
              }
            })
        .when(smbFile)
        .send(any(SmbComReadAndX.class), any(SmbComReadAndXResponse.class));

    // Read a byte array and assert its contents
    byte[] buffer = new byte[testData.length];
    int bytesRead = smbRandomAccessFile.read(buffer);
    assertEquals(testData.length, bytesRead);
    assertArrayEquals(testData, buffer);
  }

  @Test
  void testWrite() throws SmbException {
    final int testByte = 66; // 'B'

    // Mock the send method to simulate writing a single byte
    doAnswer(
            new Answer<Void>() {
              @Override
              public Void answer(InvocationOnMock invocation) throws Throwable {
                SmbComWriteAndXResponse response = invocation.getArgument(1);
                response.count = 1;
                return null;
              }
            })
        .when(smbFile)
        .send(any(SmbComWriteAndX.class), any(SmbComWriteAndXResponse.class));

    // Write a single byte
    smbRandomAccessFile.write(testByte);
    assertEquals(1, smbRandomAccessFile.getFilePointer());
  }

  @Test
  void testWriteByteArray() throws SmbException {
    final byte[] testData = "Hello, SMB!".getBytes();

    // Mock the send method to simulate writing a byte array
    doAnswer(
            new Answer<Void>() {
              @Override
              public Void answer(InvocationOnMock invocation) throws Throwable {
                SmbComWriteAndX writeAndX = invocation.getArgument(0);
                SmbComWriteAndXResponse response = invocation.getArgument(1);
                response.count = writeAndX.dataLength;
                return null;
              }
            })
        .when(smbFile)
        .send(any(SmbComWriteAndX.class), any(SmbComWriteAndXResponse.class));

    // Write a byte array
    smbRandomAccessFile.write(testData);
    assertEquals(testData.length, smbRandomAccessFile.getFilePointer());
  }

  @Test
  void testSeek() throws SmbException {
    // Seek to a new position and assert the file pointer
    long newPosition = 123L;
    smbRandomAccessFile.seek(newPosition);
    assertEquals(newPosition, smbRandomAccessFile.getFilePointer());
  }

  @Test
  void testLength() throws SmbException {
    // Mock the length method of SmbFile
    long fileLength = 456L;
    when(smbFile.length()).thenReturn(fileLength);

    // Get the file length and assert its value
    assertEquals(fileLength, smbRandomAccessFile.length());
  }

  @Test
  void testSetLength() throws SmbException {
    // Set a new file length
    long newLength = 789L;
    smbRandomAccessFile.setLength(newLength);
  }

  @Test
  void testClose() throws SmbException {
    // Close the file
    smbRandomAccessFile.close();
  }

  @Test
  void testReadFully() throws SmbException {
    final byte[] testData = "This is a test string.".getBytes();
    final int len = testData.length;
    final byte[] buffer = new byte[len];

    // Mock the read method to return data in chunks
    doAnswer(
            new Answer<Integer>() {
              private int count = 0;

              @Override
              public Integer answer(InvocationOnMock invocation) throws Throwable {
                byte[] b = invocation.getArgument(0);
                int off = invocation.getArgument(1);
                int l = invocation.getArgument(2);
                if (count >= len) {
                  return -1;
                }
                int bytesToRead = Math.min(l, len - count);
                System.arraycopy(testData, count, b, off, bytesToRead);
                count += bytesToRead;
                return bytesToRead;
              }
            })
        .when(smbFile)
        .send(any(SmbComReadAndX.class), any(SmbComReadAndXResponse.class));

    // Read the data fully and assert its contents
    smbRandomAccessFile.readFully(buffer);
    assertArrayEquals(testData, buffer);
  }

  @Test
  void testSkipBytes() throws SmbException {
    // Skip a number of bytes and assert the file pointer
    int bytesToSkip = 10;
    long initialPointer = smbRandomAccessFile.getFilePointer();
    int skippedBytes = smbRandomAccessFile.skipBytes(bytesToSkip);
    assertEquals(bytesToSkip, skippedBytes);
    assertEquals(initialPointer + bytesToSkip, smbRandomAccessFile.getFilePointer());
  }

  @Test
  void testReadWriteDataTypes() throws SmbException, IOException {
    // Mock the send method for both read and write operations
    final byte[] buffer = new byte[1024];
    final int[] bufferOffset = {0};

    doAnswer(
            new Answer<Void>() {
              @Override
              public Void answer(InvocationOnMock invocation) throws Throwable {
                SmbComWriteAndX writeAndX = invocation.getArgument(0);
                SmbComWriteAndXResponse response = invocation.getArgument(1);
                System.arraycopy(
                    writeAndX.b, writeAndX.off, buffer, bufferOffset[0], writeAndX.dataLength);
                bufferOffset[0] += writeAndX.dataLength;
                response.count = writeAndX.dataLength;
                return null;
              }
            })
        .when(smbFile)
        .send(any(SmbComWriteAndX.class), any(SmbComWriteAndXResponse.class));

    doAnswer(
            new Answer<Void>() {
              @Override
              public Void answer(InvocationOnMock invocation) throws Throwable {
                SmbComReadAndX readAndX = invocation.getArgument(0);
                SmbComReadAndXResponse response = invocation.getArgument(1);
                int bytesToRead = Math.min(readAndX.maxCount, bufferOffset[0] - (int) readAndX.offset);
                if (bytesToRead < 0) {
                  bytesToRead = 0;
                }
                System.arraycopy(
                    buffer, (int) readAndX.offset, response.b, response.off, bytesToRead);
                response.dataLength = bytesToRead;
                return null;
              }
            })
        .when(smbFile)
        .send(any(SmbComReadAndX.class), any(SmbComReadAndXResponse.class));

    // Write and read various data types
    smbRandomAccessFile.writeBoolean(true);
    smbRandomAccessFile.writeByte(123);
    smbRandomAccessFile.writeShort(456);
    smbRandomAccessFile.writeChar('A');
    smbRandomAccessFile.writeInt(789);
    smbRandomAccessFile.writeLong(1234567890L);
    smbRandomAccessFile.writeFloat(1.23f);
    smbRandomAccessFile.writeDouble(4.56);
    smbRandomAccessFile.writeBytes("test");
    smbRandomAccessFile.writeChars("test");
    smbRandomAccessFile.writeUTF("testUTF");

    smbRandomAccessFile.seek(0);

    assertEquals(true, smbRandomAccessFile.readBoolean());
    assertEquals(123, smbRandomAccessFile.readByte());
    assertEquals(456, smbRandomAccessFile.readShort());
    assertEquals('A', smbRandomAccessFile.readChar());
    assertEquals(789, smbRandomAccessFile.readInt());
    assertEquals(1234567890L, smbRandomAccessFile.readLong());
    assertEquals(1.23f, smbRandomAccessFile.readFloat(), 0.001f);
    assertEquals(4.56, smbRandomAccessFile.readDouble(), 0.001);

    byte[] bytes = new byte[4];
    smbRandomAccessFile.readFully(bytes);
    assertEquals("test", new String(bytes));

    char[] chars = new char[4];
    for (int i = 0; i < 4; i++) {
      chars[i] = smbRandomAccessFile.readChar();
    }
    assertEquals("test", new String(chars));

    assertEquals("testUTF", smbRandomAccessFile.readUTF());
  }
}
