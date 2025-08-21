/*
 * © 2025 CodeLibs, Inc.
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
 */
package jcifs.internal.smb2.persistent;

/**
 * Enumeration of SMB2/3 handle types supporting durability and persistence.
 *
 * @author jcifs team
 */
public enum HandleType {
    /**
     * No durability - standard handle
     */
    NONE(0),

    /**
     * SMB 2.1 durable handle - survives network loss
     */
    DURABLE_V1(1),

    /**
     * SMB 3.0 durable handle V2 - with timeout configuration
     */
    DURABLE_V2(2),

    /**
     * SMB 3.0 persistent handle - survives server reboot
     */
    PERSISTENT(3);

    private final int value;

    HandleType(int value) {
        this.value = value;
    }

    /**
     * Get the numeric value of this handle type
     * @return the numeric value
     */
    public int getValue() {
        return value;
    }

    /**
     * Get HandleType from numeric value
     * @param value the numeric value
     * @return the corresponding HandleType
     */
    public static HandleType fromValue(int value) {
        for (HandleType type : values()) {
            if (type.value == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown handle type value: " + value);
    }
}
