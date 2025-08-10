/*
 * Copyright 2021 Shinsuke Tsuchiya
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
package jcifs.pac;

import org.bouncycastle.asn1.*;
import org.junit.jupiter.api.Test;
import jcifs.pac.PACDecodingException;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Vector;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the {@link ASN1Util} class.
 */
class ASN1UtilTest {

    // --- as(Class, Object) ---

    @Test
    void testAs_Object_Success() throws PACDecodingException {
        // Test successful casting
        String expected = "test string";
        Object obj = expected;
        String result = ASN1Util.as(String.class, obj);
        assertSame(expected, result);
    }

    @Test
    void testAs_Object_Failure() {
        // Test failed casting
        Object obj = 123; // Integer
        assertThrows(PACDecodingException.class, () -> {
            ASN1Util.as(String.class, obj);
        }, "Should throw PACDecodingException for incompatible types");
    }

    // --- as(Class, Enumeration) ---

    @Test
    void testAs_Enumeration_Success() throws PACDecodingException {
        // Test successful casting from enumeration
        Vector<ASN1Integer> vector = new Vector<>();
        ASN1Integer expected = new ASN1Integer(123);
        vector.add(expected);
        ASN1Integer result = ASN1Util.as(ASN1Integer.class, vector.elements());
        assertSame(expected, result);
    }

    @Test
    void testAs_Enumeration_Failure() {
        // Test failed casting from enumeration
        Vector<ASN1Integer> vector = new Vector<>();
        vector.add(new ASN1Integer(123));
        assertThrows(PACDecodingException.class, () -> {
            ASN1Util.as(ASN1Boolean.class, vector.elements());
        }, "Should throw PACDecodingException for incompatible types in enumeration");
    }

    // --- as(Class, ASN1InputStream) ---

    @Test
    void testAs_ASN1InputStream_Success() throws IOException, PACDecodingException {
        // Test successful reading and casting from ASN1InputStream
        ASN1Integer original = new ASN1Integer(456);
        ByteArrayInputStream bais = new ByteArrayInputStream(original.getEncoded());
        ASN1InputStream ais = new ASN1InputStream(bais);
        ASN1Integer result = ASN1Util.as(ASN1Integer.class, ais);
        assertEquals(original, result);
    }

    @Test
    void testAs_ASN1InputStream_Failure() throws IOException {
        // Test failed casting from ASN1InputStream
        ASN1Boolean original = ASN1Boolean.TRUE;
        ByteArrayInputStream bais = new ByteArrayInputStream(original.getEncoded());
        ASN1InputStream ais = new ASN1InputStream(bais);
        assertThrows(PACDecodingException.class, () -> {
            ASN1Util.as(ASN1Integer.class, ais);
        }, "Should throw PACDecodingException for incompatible types in stream");
    }

    // --- as(Class, ASN1TaggedObject) ---

    @Test
    void testAs_ASN1TaggedObject_Success() throws PACDecodingException {
        // Test successful casting from tagged object
        ASN1Integer content = new ASN1Integer(789);
        ASN1TaggedObject tagged = new DERTaggedObject(true, 1, content);
        ASN1Integer result = ASN1Util.as(ASN1Integer.class, tagged);
        assertSame(content, result);
    }

    @Test
    void testAs_ASN1TaggedObject_Failure() {
        // Test failed casting from tagged object
        ASN1Integer content = new ASN1Integer(789);
        ASN1TaggedObject tagged = new DERTaggedObject(true, 1, content);
        assertThrows(PACDecodingException.class, () -> {
            ASN1Util.as(ASN1Boolean.class, tagged);
        }, "Should throw PACDecodingException for incompatible types in tagged object");
    }

    // --- as(Class, ASN1Sequence, int) ---

    @Test
    void testAs_ASN1Sequence_Success() throws PACDecodingException {
        // Test successful casting from sequence
        ASN1EncodableVector vector = new ASN1EncodableVector();
        ASN1Integer expected = new ASN1Integer(10);
        vector.add(expected);
        ASN1Sequence sequence = new DERSequence(vector);
        ASN1Integer result = ASN1Util.as(ASN1Integer.class, sequence, 0);
        assertSame(expected, result);
    }

    @Test
    void testAs_ASN1Sequence_Failure() {
        // Test failed casting from sequence
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(10));
        ASN1Sequence sequence = new DERSequence(vector);
        assertThrows(PACDecodingException.class, () -> {
            ASN1Util.as(ASN1Boolean.class, sequence, 0);
        }, "Should throw PACDecodingException for incompatible types in sequence");
    }

    // --- as(Class, DLSequence, int) ---

    @Test
    void testAs_DLSequence_RecursiveBug() {
        // This test exposes a recursive bug in the current implementation
        // The method calls itself, leading to a StackOverflowError.
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(10));
        DLSequence sequence = new DLSequence(vector);
        assertThrows(StackOverflowError.class, () -> {
            ASN1Util.as(ASN1Integer.class, sequence, 0);
        }, "Should throw StackOverflowError due to recursive call");
    }

    // --- readUnparsedTagged ---

    @Test
    void testReadUnparsedTagged_Success() throws IOException {
        // Tag [1] IMPLICIT, content is 0x01 0x02 0x03
        byte[] data = new byte[]{(byte) 0xA1, 0x03, 0x01, 0x02, 0x03};
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ASN1InputStream ais = new ASN1InputStream(bais);
        byte[] result = ASN1Util.readUnparsedTagged(1, 10, ais);
        assertArrayEquals(new byte[]{0x01, 0x02, 0x03}, result);
    }

    @Test
    void testReadUnparsedTagged_WrongTag() {
        // Expecting tag 2, but data has tag 1
        byte[] data = new byte[]{(byte) 0xA1, 0x03, 0x01, 0x02, 0x03};
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ASN1InputStream ais = new ASN1InputStream(bais);
        assertThrows(IOException.class, () -> {
            ASN1Util.readUnparsedTagged(2, 10, ais);
        }, "Should throw IOException for unexpected tag");
    }

    // --- readTagNumber ---

    @Test
    void testReadTagNumber_Simple() throws IOException {
        // Simple tag 5
        InputStream s = new ByteArrayInputStream(new byte[]{});
        int tagNo = ASN1Util.readTagNumber(s, 0x05);
        assertEquals(5, tagNo);
    }

    @Test
    void testReadTagNumber_HighTag() throws IOException {
        // High tag number (31)
        InputStream s = new ByteArrayInputStream(new byte[]{0x1F});
        int tagNo = ASN1Util.readTagNumber(s, 0x1F);
        assertEquals(31, tagNo);
    }

    @Test
    void testReadTagNumber_MultiByte() throws IOException {
        // Multi-byte tag (e.g., 80)
        InputStream s = new ByteArrayInputStream(new byte[]{(byte) 0x81, 0x00});
        int tagNo = ASN1Util.readTagNumber(s, 0x1F);
        assertEquals(128, tagNo);
    }

    @Test
    void testReadTagNumber_CorruptedHighTag() {
        // High tag < 31
        InputStream s = new ByteArrayInputStream(new byte[]{0x1E});
        assertThrows(IOException.class, () -> {
            ASN1Util.readTagNumber(s, 0x1F);
        });
    }

    @Test
    void testReadTagNumber_EOF() {
        // EOF inside tag value
        InputStream s = new ByteArrayInputStream(new byte[]{});
        assertThrows(EOFException.class, () -> {
            ASN1Util.readTagNumber(s, 0x1F);
        });
    }

    // --- readLength ---

    @Test
    void testReadLength_ShortForm() throws IOException {
        // Definite-length short form (length 10)
        InputStream s = new ByteArrayInputStream(new byte[]{0x0A});
        int length = ASN1Util.readLength(s, 100, false);
        assertEquals(10, length);
    }

    @Test
    void testReadLength_LongForm() throws IOException {
        // Definite-length long form (length 256)
        InputStream s = new ByteArrayInputStream(new byte[]{(byte) 0x82, 0x01, 0x00});
        int length = ASN1Util.readLength(s, 500, false);
        assertEquals(256, length);
    }

    @Test
    void testReadLength_Indefinite() throws IOException {
        // Indefinite-length
        InputStream s = new ByteArrayInputStream(new byte[]{(byte) 0x80});
        int length = ASN1Util.readLength(s, 100, false);
        assertEquals(-1, length);
    }

    @Test
    void testReadLength_EOF() {
        // EOF when length expected
        InputStream s = new ByteArrayInputStream(new byte[]{});
        assertThrows(EOFException.class, () -> {
            ASN1Util.readLength(s, 100, false);
        });
    }

    @Test
    void testReadLength_OutOfBounds() {
        // Length out of bounds
        InputStream s = new ByteArrayInputStream(new byte[]{(byte) 0x81, (byte) 0xFF}); // length 255
        assertThrows(IOException.class, () -> {
            ASN1Util.readLength(s, 200, false); // limit 200
        });
    }
}