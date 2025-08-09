package jcifs.internal.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for StringUtil utility methods
 */
class StringUtilTest {

    @Test
    @DisplayName("Should join single element without delimiter")
    void testJoinSingleElement() {
        String result = StringUtil.join(",", "hello");
        assertEquals("hello", result);
    }

    @Test
    @DisplayName("Should join two elements with delimiter")
    void testJoinTwoElements() {
        String result = StringUtil.join(",", "hello", "world");
        assertEquals("hello,world", result);
    }

    @Test
    @DisplayName("Should join multiple elements with delimiter")
    void testJoinMultipleElements() {
        String result = StringUtil.join(",", "one", "two", "three", "four");
        assertEquals("one,two,three,four", result);
    }

    @Test
    @DisplayName("Should join with empty string delimiter")
    void testJoinWithEmptyDelimiter() {
        String result = StringUtil.join("", "hello", "world");
        assertEquals("helloworld", result);
    }

    @Test
    @DisplayName("Should join with multi-character delimiter")
    void testJoinWithMultiCharDelimiter() {
        String result = StringUtil.join(" - ", "apple", "banana", "cherry");
        assertEquals("apple - banana - cherry", result);
    }

    @Test
    @DisplayName("Should handle null delimiter by inserting 'null' string")
    void testJoinWithNullDelimiter() {
        String result = StringUtil.join(null, "first", "second", "third");
        assertEquals("firstnullsecondnullthird", result);
    }

    @Test
    @DisplayName("Should handle null elements in array")
    void testJoinWithNullElements() {
        String result = StringUtil.join(",", "first", null, "third");
        assertEquals("first,null,third", result);
    }

    @Test
    @DisplayName("Should handle all null elements")
    void testJoinWithAllNullElements() {
        String result = StringUtil.join(",", null, null, null);
        assertEquals("null,null,null", result);
    }

    @Test
    @DisplayName("Should handle empty string elements")
    void testJoinWithEmptyStringElements() {
        String result = StringUtil.join(",", "", "middle", "");
        // First element is empty string (sb becomes "")
        // Second: sb.length() is 0, no delimiter, append "middle" (sb becomes "middle")  
        // Third: sb.length() > 0, add delimiter + "" (sb becomes "middle,")
        assertEquals("middle,", result);
    }

    @Test
    @DisplayName("Should handle mix of empty and null elements")
    void testJoinWithMixedEmptyAndNull() {
        String result = StringUtil.join("-", "", null, "value", "", null);
        // First: "" (sb becomes "")
        // Second: sb.length() is 0, no delimiter, append null (sb becomes "null")
        // Third: sb.length() > 0, add "-" + "value" (sb becomes "null-value")
        // Fourth: sb.length() > 0, add "-" + "" (sb becomes "null-value-")
        // Fifth: sb.length() > 0, add "-" + null (sb becomes "null-value--null")
        assertEquals("null-value--null", result);
    }

    @Test
    @DisplayName("Should return empty string for zero elements")
    void testJoinWithNoElements() {
        String result = StringUtil.join(",");
        assertEquals("", result);
    }

    @Test
    @DisplayName("Should handle special characters in delimiter")
    void testJoinWithSpecialCharDelimiter() {
        String result = StringUtil.join("\\t", "tab", "separated", "values");
        assertEquals("tab\\tseparated\\tvalues", result);
    }

    @Test
    @DisplayName("Should handle Unicode characters in delimiter")
    void testJoinWithUnicodeDelimiter() {
        String result = StringUtil.join("→", "left", "right");
        assertEquals("left→right", result);
    }

    @Test
    @DisplayName("Should handle Unicode characters in elements")
    void testJoinWithUnicodeElements() {
        String result = StringUtil.join(",", "日本語", "中文", "한국어");
        assertEquals("日本語,中文,한국어", result);
    }

    @ParameterizedTest
    @DisplayName("Should handle various delimiter types")
    @MethodSource("provideDelimiters")
    void testJoinWithVariousDelimiters(String delimiter, String expected) {
        String result = StringUtil.join(delimiter, "A", "B", "C");
        assertEquals(expected, result);
    }

    private static Stream<Arguments> provideDelimiters() {
        return Stream.of(
            Arguments.of(",", "A,B,C"),
            Arguments.of(", ", "A, B, C"),
            Arguments.of(" ", "A B C"),
            Arguments.of("|", "A|B|C"),
            Arguments.of("::", "A::B::C"),
            Arguments.of("\n", "A\nB\nC"),
            Arguments.of("\r\n", "A\r\nB\r\nC")
        );
    }

    @Test
    @DisplayName("Should handle StringBuilder as CharSequence")
    void testJoinWithStringBuilder() {
        StringBuilder sb1 = new StringBuilder("first");
        StringBuilder sb2 = new StringBuilder("second");
        String result = StringUtil.join(",", sb1, sb2);
        assertEquals("first,second", result);
    }

    @Test
    @DisplayName("Should handle StringBuffer as CharSequence")
    void testJoinWithStringBuffer() {
        StringBuffer sb1 = new StringBuffer("alpha");
        StringBuffer sb2 = new StringBuffer("beta");
        String result = StringUtil.join("-", sb1, sb2);
        assertEquals("alpha-beta", result);
    }

    @Test
    @DisplayName("Should handle mixed CharSequence types")
    void testJoinWithMixedCharSequenceTypes() {
        String str = "string";
        StringBuilder builder = new StringBuilder("builder");
        StringBuffer buffer = new StringBuffer("buffer");
        String result = StringUtil.join(",", str, builder, buffer);
        assertEquals("string,builder,buffer", result);
    }

    @ParameterizedTest
    @DisplayName("Should handle various element counts")
    @ValueSource(ints = {1, 2, 5, 10, 20, 50, 100})
    void testJoinWithVariousElementCounts(int count) {
        CharSequence[] elements = new CharSequence[count];
        for (int i = 0; i < count; i++) {
            elements[i] = String.valueOf(i);
        }
        String result = StringUtil.join(",", elements);
        
        // Verify result contains all elements
        String[] parts = result.split(",");
        assertEquals(count, parts.length);
        for (int i = 0; i < count; i++) {
            assertEquals(String.valueOf(i), parts[i]);
        }
    }

    @Test
    @DisplayName("Should handle long strings as elements")
    void testJoinWithLongStrings() {
        String longString1 = "a".repeat(1000);
        String longString2 = "b".repeat(1000);
        String result = StringUtil.join(",", longString1, longString2);
        assertEquals(2001, result.length()); // 1000 + 1 + 1000
        assertTrue(result.startsWith("aaa"));
        assertTrue(result.endsWith("bbb"));
        assertTrue(result.contains(","));
    }

    @Test
    @DisplayName("Should handle long delimiter")
    void testJoinWithLongDelimiter() {
        String longDelimiter = "=".repeat(100);
        String result = StringUtil.join(longDelimiter, "A", "B");
        assertEquals("A" + longDelimiter + "B", result);
    }

    @Test
    @DisplayName("Should preserve element order")
    void testJoinPreservesOrder() {
        String result = StringUtil.join(",", "z", "y", "x", "w", "v");
        assertEquals("z,y,x,w,v", result);
    }

    @Test
    @DisplayName("Should handle delimiter as CharSequence subtype")
    void testJoinWithCharSequenceDelimiter() {
        StringBuilder delimiter = new StringBuilder(" | ");
        String result = StringUtil.join(delimiter, "one", "two");
        assertEquals("one | two", result);
    }

    @Test
    @DisplayName("Should handle single null element")
    void testJoinSingleNullElement() {
        String result = StringUtil.join(",", (CharSequence) null);
        assertEquals("null", result);
    }

    @Test
    @DisplayName("Should handle whitespace delimiter")
    void testJoinWithWhitespaceDelimiter() {
        String result = StringUtil.join("   ", "spaced", "out");
        assertEquals("spaced   out", result);
    }

    @Test
    @DisplayName("Should handle elements containing delimiter")
    void testJoinElementsContainingDelimiter() {
        String result = StringUtil.join(",", "a,b", "c,d", "e,f");
        assertEquals("a,b,c,d,e,f", result);
    }

    @Test
    @DisplayName("Should handle empty array")
    void testJoinEmptyArray() {
        CharSequence[] empty = new CharSequence[0];
        String result = StringUtil.join(",", empty);
        assertEquals("", result);
    }

    @Test
    @DisplayName("Should handle null in middle of multiple elements")
    void testJoinNullInMiddle() {
        String result = StringUtil.join("-", "start", null, null, "end");
        assertEquals("start-null-null-end", result);
    }
}