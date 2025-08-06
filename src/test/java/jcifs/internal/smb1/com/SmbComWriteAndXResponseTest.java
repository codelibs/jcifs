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

import jcifs.CIFSContext;
import jcifs.config.PropertyConfiguration;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Properties;

public class SmbComWriteAndXResponseTest {

    /**
     * Test of readParameterWordsWireFormat method, of class
     * SmbComWriteAndXResponse.
     */
    @Test
    public void testReadParameterWordsWireFormat() {
        // Given
        byte[] buffer = new byte[] { (byte) 0xff, (byte) 0xff, 0, 0, 0, 0, 0, 0 };
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(
                new PropertyConfiguration(new Properties()).getSmb1Context());

        // When
        int result = instance.readParameterWordsWireFormat(buffer, 0);

        // Then
        assertEquals(8, result);
        assertEquals(0xffffL, instance.getCount());
    }

    /**
     * Test of toString method, of class SmbComWriteAndXResponse.
     */
    @Test
    public void testToString() {
        // Given
        SmbComWriteAndXResponse instance = new SmbComWriteAndXResponse(
                new PropertyConfiguration(new Properties()).getSmb1Context());

        // When
        String result = instance.toString();

        // Then
        assertEquals("SmbComWriteAndXResponse[SmbComWriteAndXResponse[command=SMB_COM_WRITE_ANDX,received=false,errorCode=0,flags=0x0,flags2=0x0,signSeq=0,tid=0,pid=0,uid=0,mid=0,wordCount=0,byteCount=0,andxCommand=0xFF,andxOffset=0],count=0]", result);
    }
}