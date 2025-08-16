/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
package jcifs.internal.dtyp;

import jcifs.Decodable;

/**
 * Interface for Windows Data Type (DTYP) security information structures.
 * Defines constants and functionality for security information types used in
 * SMB security descriptor operations and access control management.
 *
 * @author mbechler
 */
public interface SecurityInfo extends Decodable {

    /**
     * Flag indicating that owner security information is requested or being set.
     */
    int OWNER_SECURITY_INFO = 0x1;

    /**
     * Flag indicating that group security information is requested or being set.
     */
    int GROUP_SECURITY_INFO = 0x2;

    /**
     * Flag indicating that discretionary access control list (DACL) information is requested or being set.
     */
    int DACL_SECURITY_INFO = 0x4;

    /**
     * Flag indicating that system access control list (SACL) information is requested or being set.
     */
    int SACL_SECURITY_INFO = 0x8;

    /**
     * Flag indicating that mandatory label information is requested or being set.
     */
    int LABEL_SECURITY_INFO = 0x10;

    /**
     * Flag indicating that attribute security information is requested or being set.
     */
    int ATTRIBUTE_SECURITY_INFO = 0x20;

    /**
     * Flag indicating that central access policy information is requested or being set.
     */
    int SCOPE_SECURITY_INFO = 0x40;

    /**
     * Flag indicating that backup security information is requested or being set.
     */
    int BACKUP_SECURITY_INFO = 0x1000;
}
