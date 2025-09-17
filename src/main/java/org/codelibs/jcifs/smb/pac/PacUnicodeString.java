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
package org.codelibs.jcifs.smb.pac;

/**
 * Represents a Unicode string structure as used in PAC data.
 * This class encapsulates the metadata for a Unicode string including its length,
 * maximum length, and pointer to the actual string data.
 */
public class PacUnicodeString {

    private final short length;
    private final short maxLength;
    private final int pointer;

    /**
     * Constructs a new PacUnicodeString instance.
     *
     * @param length the actual length of the string in bytes
     * @param maxLength the maximum allocated length for the string in bytes
     * @param pointer the pointer/offset to the string data
     */
    public PacUnicodeString(final short length, final short maxLength, final int pointer) {
        this.length = length;
        this.maxLength = maxLength;
        this.pointer = pointer;
    }

    /**
     * Gets the actual length of the string in bytes.
     *
     * @return the string length
     */
    public short getLength() {
        return this.length;
    }

    /**
     * Gets the maximum allocated length for the string in bytes.
     *
     * @return the maximum string length
     */
    public short getMaxLength() {
        return this.maxLength;
    }

    /**
     * Gets the pointer/offset to the string data.
     *
     * @return the pointer to the string data
     */
    public int getPointer() {
        return this.pointer;
    }

    /**
     * Validates the provided string against this structure's metadata.
     * Checks that the string length matches the expected length and that
     * null strings have a zero pointer.
     *
     * @param string the string to validate
     * @return the validated string
     * @throws PACDecodingException if validation fails
     */
    public String check(final String string) throws PACDecodingException {
        if (this.pointer == 0 && string != null) {
            throw new PACDecodingException("Non-empty string");
        }

        final int expected = this.length / 2;
        if (string.length() != expected) {
            throw new PACDecodingException("Invalid string length, expected " + expected + ", have " + string.length());
        }

        return string;
    }
}
