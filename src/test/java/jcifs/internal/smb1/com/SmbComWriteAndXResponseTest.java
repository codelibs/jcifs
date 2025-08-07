/*
 * Copyright 2024 The JCIFS Authors
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
package jcifs.internal.smb1.com;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.config.PropertyConfiguration;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Properties;

public class SmbComWriteAndXResponseTest {

    private Configuration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        config = new PropertyConfiguration(new Properties());
    }

    /**
     * Test of readParameterWordsWireFormat method
     */
    @Test
    public void testReadParameterWordsWireFormat() {
        // Given
        byte[] buffer = new byte[] { (byte) 0xff, (byte) 0xff, 0, 0, 0, 0, 0, 0 };
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        int result = instance.readParameterWordsWireFormat(buffer, 0);

        // Then
        assertEquals(8, result);
        assertEquals(0xffffL, instance.getCount());
    }

    /**
     * Test of readParameterWordsWireFormat with zero count
     */
    @Test
    public void testReadParameterWordsWireFormatZeroCount() {
        // Given
        byte[] buffer = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        int result = instance.readParameterWordsWireFormat(buffer, 0);

        // Then
        assertEquals(8, result);
        assertEquals(0L, instance.getCount());
    }

    /**
     * Test of writeParameterWordsWireFormat method
     */
    @Test
    public void testWriteParameterWordsWireFormat() {
        // Given
        byte[] buffer = new byte[10];
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        int result = instance.writeParameterWordsWireFormat(buffer, 0);

        // Then
        assertEquals(0, result);
    }

    /**
     * Test of writeBytesWireFormat method
     */
    @Test
    public void testWriteBytesWireFormat() {
        // Given
        byte[] buffer = new byte[10];
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        int result = instance.writeBytesWireFormat(buffer, 0);

        // Then
        assertEquals(0, result);
    }

    /**
     * Test of readBytesWireFormat method
     */
    @Test
    public void testReadBytesWireFormat() {
        // Given
        byte[] buffer = new byte[10];
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        int result = instance.readBytesWireFormat(buffer, 0);

        // Then
        assertEquals(0, result);
    }

    /**
     * Test of toString method
     */
    @Test
    public void testToString() {
        // Given
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(config);

        // When
        String result = instance.toString();

        // Then
        assertNotNull(result);
        assertTrue(result.contains("SmbComWriteAndXResponse"));
        assertTrue(result.contains("count=0"));
    }
}