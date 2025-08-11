/*
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package jcifs.pac;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;

/**
 * Tests for the PACDecodingException class.
 */
class PACDecodingExceptionTest {

    /**
     * Test the default constructor.
     */
    @Test
    void testDefaultConstructor() {
        PACDecodingException e = new PACDecodingException();
        // Expect null message and null cause
        assertNull(e.getMessage());
        assertNull(e.getCause());
    }

    /**
     * Test the constructor with a message.
     */
    @Test
    void testMessageConstructor() {
        String errorMessage = "This is a test error message.";
        PACDecodingException e = new PACDecodingException(errorMessage);
        // Expect the message to be set correctly and cause to be null
        assertEquals(errorMessage, e.getMessage());
        assertNull(e.getCause());
    }

    /**
     * Test the constructor with a cause.
     */
    @Test
    void testCauseConstructor() {
        Throwable cause = new RuntimeException("Root cause");
        PACDecodingException e = new PACDecodingException(cause);
        // When constructed with only a cause, the implementation passes (null, cause) to super
        // which results in a null message rather than deriving it from the cause
        assertNull(e.getMessage());
        assertSame(cause, e.getCause());
    }

    /**
     * Test the constructor with both a message and a cause.
     */
    @Test
    void testMessageAndCauseConstructor() {
        String errorMessage = "This is a test error message.";
        Throwable cause = new RuntimeException("Root cause");
        PACDecodingException e = new PACDecodingException(errorMessage, cause);
        // Expect both the message and the cause to be set correctly
        assertEquals(errorMessage, e.getMessage());
        assertSame(cause, e.getCause());
    }
}