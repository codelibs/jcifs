/*
 * Copyright 2024 The gptoss authors.
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

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jcifs.smb1.smb1.SmbComNtTransactionResponse;

class SmbComNtTransactionResponseTest {

    private TestableSmbComNtTransactionResponse response;

    // A concrete implementation of the abstract class for testing purposes.
    private static class TestableSmbComNtTransactionResponse extends SmbComNtTransactionResponse {
        @Override
        int writeSetupWireFormat(byte[] dst, int dstIndex) {
            return 0;
        }

        @Override
        int writeParametersWireFormat(byte[] dst, int dstIndex) {
            return 0;
        }

        @Override
        int writeDataWireFormat(byte[] dst, int dstIndex) {
            return 0;
        }

        @Override
        int readSetupWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 0;
        }

        @Override
        int readParametersWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 0;
        }

        @Override
        int readDataWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 0;
        }
    }

    @BeforeEach
    void setUp() {
        response = new TestableSmbComNtTransactionResponse();
    }

    @Test
    void testReadParameterWordsWireFormat_bufDataStartIsZero() {
        // Test case when bufDataStart is initially 0.
        byte[] buffer = new byte[37]; // 3 reserved + 8*4 bytes for int4 values + 2 bytes for setupCount
        int bufferIndex = 0;

        // Reserved bytes
        buffer[bufferIndex++] = 0x00;
        buffer[bufferIndex++] = 0x00;
        buffer[bufferIndex++] = 0x00;

        // totalParameterCount = 10
        writeInt4(10, buffer, bufferIndex);
        bufferIndex += 4;
        // totalDataCount = 20
        writeInt4(20, buffer, bufferIndex);
        bufferIndex += 4;
        // parameterCount = 5
        writeInt4(5, buffer, bufferIndex);
        bufferIndex += 4;
        // parameterOffset = 30
        writeInt4(30, buffer, bufferIndex);
        bufferIndex += 4;
        // parameterDisplacement = 0
        writeInt4(0, buffer, bufferIndex);
        bufferIndex += 4;
        // dataCount = 15
        writeInt4(15, buffer, bufferIndex);
        bufferIndex += 4;
        // dataOffset = 40
        writeInt4(40, buffer, bufferIndex);
        bufferIndex += 4;
        // dataDisplacement = 0
        writeInt4(0, buffer, bufferIndex);
        bufferIndex += 4;
        // setupCount = 0 (1 byte + 1 padding byte)
        buffer[bufferIndex] = 0;
        buffer[bufferIndex + 1] = 0; // padding byte

        int bytesRead = response.readParameterWordsWireFormat(buffer, 0);

        assertEquals(37, bytesRead); // 3 reserved + 32 (8*4) + 2 for setupCount
        assertEquals(10, response.totalParameterCount);
        assertEquals(10, response.bufDataStart); // Should be set to totalParameterCount
        assertEquals(20, response.totalDataCount);
        assertEquals(5, response.parameterCount);
        assertEquals(30, response.parameterOffset);
        assertEquals(0, response.parameterDisplacement);
        assertEquals(15, response.dataCount);
        assertEquals(40, response.dataOffset);
        assertEquals(0, response.dataDisplacement);
        assertEquals(0, response.setupCount);
    }

    @Test
    void testReadParameterWordsWireFormat_bufDataStartIsNotZero() {
        // Test case when bufDataStart is not 0.
        response.bufDataStart = 50; // Initial non-zero value
        byte[] buffer = new byte[37]; // 3 reserved + 8*4 bytes for int4 values + 2 bytes for setupCount
        int bufferIndex = 0;

        // Reserved bytes
        buffer[bufferIndex++] = 0x00;
        buffer[bufferIndex++] = 0x00;
        buffer[bufferIndex++] = 0x00;

        // totalParameterCount = 10
        writeInt4(10, buffer, bufferIndex);
        bufferIndex += 4;
        // totalDataCount = 20
        writeInt4(20, buffer, bufferIndex);
        bufferIndex += 4;
        // parameterCount = 5
        writeInt4(5, buffer, bufferIndex);
        bufferIndex += 4;
        // parameterOffset = 30
        writeInt4(30, buffer, bufferIndex);
        bufferIndex += 4;
        // parameterDisplacement = 0
        writeInt4(0, buffer, bufferIndex);
        bufferIndex += 4;
        // dataCount = 15
        writeInt4(15, buffer, bufferIndex);
        bufferIndex += 4;
        // dataOffset = 40
        writeInt4(40, buffer, bufferIndex);
        bufferIndex += 4;
        // dataDisplacement = 0
        writeInt4(0, buffer, bufferIndex);
        bufferIndex += 4;
        // setupCount = 1 (1 byte + 1 padding byte)
        buffer[bufferIndex] = 1;
        buffer[bufferIndex + 1] = 0; // padding byte

        int bytesRead = response.readParameterWordsWireFormat(buffer, 0);

        assertEquals(37, bytesRead); // 3 reserved + 32 (8*4) + 2 for setupCount
        assertEquals(10, response.totalParameterCount);
        assertEquals(50, response.bufDataStart); // Should not be changed
        assertEquals(20, response.totalDataCount);
        assertEquals(5, response.parameterCount);
        assertEquals(30, response.parameterOffset);
        assertEquals(0, response.parameterDisplacement);
        assertEquals(15, response.dataCount);
        assertEquals(40, response.dataOffset);
        assertEquals(0, response.dataDisplacement);
        assertEquals(1, response.setupCount);
    }

    // Helper method to write a 4-byte integer to a byte array.
    private void writeInt4(int val, byte[] dst, int dstIndex) {
        dst[dstIndex] = (byte) val;
        dst[dstIndex + 1] = (byte) (val >> 8);
        dst[dstIndex + 2] = (byte) (val >> 16);
        dst[dstIndex + 3] = (byte) (val >> 24);
    }
}
