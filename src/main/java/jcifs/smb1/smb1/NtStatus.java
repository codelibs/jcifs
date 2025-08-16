/* jcifs smb client library in Java
 * Copyright (C) 2004  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.smb1.smb1;

/**
 * Interface defining NT status codes used in SMB1 protocol operations.
 * These status codes are returned by SMB servers to indicate the result
 * of requested operations. The codes follow the Windows NT status code format.
 */
public interface NtStatus {

    /* Don't bother to edit this. Everthing within the interface
     * block is automatically generated from the ntstatus package.
     */

    /** @deprecated Use NT_STATUS_SUCCESS instead */
    int NT_STATUS_OK = 0x00000000; // TODO: Remove this constant, use NT_STATUS_SUCCESS instead.
    /** The operation completed successfully */
    int NT_STATUS_SUCCESS = 0x00000000;
    /** The requested operation was unsuccessful */
    int NT_STATUS_UNSUCCESSFUL = 0xC0000001;
    /** The requested operation is not implemented */
    int NT_STATUS_NOT_IMPLEMENTED = 0xC0000002;
    /** The specified information class is invalid */
    int NT_STATUS_INVALID_INFO_CLASS = 0xC0000003;
    /** Invalid access to memory location */
    int NT_STATUS_ACCESS_VIOLATION = 0xC0000005;
    /** The handle is invalid */
    int NT_STATUS_INVALID_HANDLE = 0xC0000008;
    /** The parameter is incorrect */
    int NT_STATUS_INVALID_PARAMETER = 0xC000000d;
    /** The system cannot find the device specified */
    int NT_STATUS_NO_SUCH_DEVICE = 0xC000000e;
    /** The system cannot find the file specified */
    int NT_STATUS_NO_SUCH_FILE = 0xC000000f;
    /** More processing is required to complete this request */
    int NT_STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016;
    /** Access is denied */
    int NT_STATUS_ACCESS_DENIED = 0xC0000022;
    /** The data area passed to a system call is too small */
    int NT_STATUS_BUFFER_TOO_SMALL = 0xC0000023;
    /** The object name is invalid */
    int NT_STATUS_OBJECT_NAME_INVALID = 0xC0000033;
    /** The object was not found */
    int NT_STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;
    /** The object name already exists */
    int NT_STATUS_OBJECT_NAME_COLLISION = 0xC0000035;
    /** The port is disconnected */
    int NT_STATUS_PORT_DISCONNECTED = 0xC0000037;
    /** The object path is invalid */
    int NT_STATUS_OBJECT_PATH_INVALID = 0xC0000039;
    /** The object path was not found */
    int NT_STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003a;
    /** The object path syntax is bad */
    int NT_STATUS_OBJECT_PATH_SYNTAX_BAD = 0xC000003b;
    /** The process cannot access the file because it is being used by another process */
    int NT_STATUS_SHARING_VIOLATION = 0xC0000043;
    /** The file is pending deletion */
    int NT_STATUS_DELETE_PENDING = 0xC0000056;
    /** There are currently no logon servers available to service the logon request */
    int NT_STATUS_NO_LOGON_SERVERS = 0xC000005e;
    /** The specified user already exists */
    int NT_STATUS_USER_EXISTS = 0xC0000063;
    /** The specified user does not exist */
    int NT_STATUS_NO_SUCH_USER = 0xC0000064;
    /** The specified network password is not correct */
    int NT_STATUS_WRONG_PASSWORD = 0xC000006a;
    /** Logon failure: unknown user name or bad password */
    int NT_STATUS_LOGON_FAILURE = 0xC000006d;
    /** Logon failure: user account restriction */
    int NT_STATUS_ACCOUNT_RESTRICTION = 0xC000006e;
    /** Logon failure: account logon time restriction violation */
    int NT_STATUS_INVALID_LOGON_HOURS = 0xC000006f;
    /** Logon failure: user not allowed to log on to this computer */
    int NT_STATUS_INVALID_WORKSTATION = 0xC0000070;
    /** The user's password has expired */
    int NT_STATUS_PASSWORD_EXPIRED = 0xC0000071;
    /** The referenced account is currently disabled */
    int NT_STATUS_ACCOUNT_DISABLED = 0xC0000072;
    /** No mapping between account names and security IDs was done */
    int NT_STATUS_NONE_MAPPED = 0xC0000073;
    /** The security ID structure is invalid */
    int NT_STATUS_INVALID_SID = 0xC0000078;
    /** The requested pipe instance is not available */
    int NT_STATUS_INSTANCE_NOT_AVAILABLE = 0xC00000ab;
    /** The pipe is not available */
    int NT_STATUS_PIPE_NOT_AVAILABLE = 0xC00000ac;
    /** The pipe state is invalid for the requested operation */
    int NT_STATUS_INVALID_PIPE_STATE = 0xC00000ad;
    /** All pipe instances are busy */
    int NT_STATUS_PIPE_BUSY = 0xC00000ae;
    /** No process is on the other end of the pipe */
    int NT_STATUS_PIPE_DISCONNECTED = 0xC00000b0;
    /** The pipe is being closed */
    int NT_STATUS_PIPE_CLOSING = 0xC00000b1;
    /** Waiting for a process to open the other end of the pipe */
    int NT_STATUS_PIPE_LISTENING = 0xC00000b3;
    /** The file that was specified is a directory */
    int NT_STATUS_FILE_IS_A_DIRECTORY = 0xC00000ba;
    /** A duplicate name exists on the network */
    int NT_STATUS_DUPLICATE_NAME = 0xC00000bd;
    /** The specified network name is no longer available */
    int NT_STATUS_NETWORK_NAME_DELETED = 0xC00000c9;
    /** Network access is denied */
    int NT_STATUS_NETWORK_ACCESS_DENIED = 0xC00000ca;
    /** The network name cannot be found */
    int NT_STATUS_BAD_NETWORK_NAME = 0xC00000cc;
    /** No more connections can be made to this remote computer */
    int NT_STATUS_REQUEST_NOT_ACCEPTED = 0xC00000d0;
    /** Indicates a domain controller could not be contacted or objects are protected */
    int NT_STATUS_CANT_ACCESS_DOMAIN_INFO = 0xC00000da;
    /** The specified domain does not exist */
    int NT_STATUS_NO_SUCH_DOMAIN = 0xC00000df;
    /** The directory name is invalid */
    int NT_STATUS_NOT_A_DIRECTORY = 0xC0000103;
    /** The file cannot be deleted */
    int NT_STATUS_CANNOT_DELETE = 0xC0000121;
    /** The format of the specified computer name is invalid */
    int NT_STATUS_INVALID_COMPUTER_NAME = 0xC0000122;
    /** The pipe operation has failed because the other end of the pipe has been closed */
    int NT_STATUS_PIPE_BROKEN = 0xC000014b;
    /** The specified local group does not exist */
    int NT_STATUS_NO_SUCH_ALIAS = 0xC0000151;
    /** The user has not been granted the requested logon type at this computer */
    int NT_STATUS_LOGON_TYPE_NOT_GRANTED = 0xC000015b;
    /** The SAM database does not have a computer account for this workstation trust relationship */
    int NT_STATUS_NO_TRUST_SAM_ACCOUNT = 0xC000018b;
    /** The trust relationship between the primary domain and the trusted domain failed */
    int NT_STATUS_TRUSTED_DOMAIN_FAILURE = 0xC000018c;
    /** The account used is a computer account */
    int NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT = 0xC0000199;
    /** The user must change the password before first logon */
    int NT_STATUS_PASSWORD_MUST_CHANGE = 0xC0000224;
    /** The object was not found */
    int NT_STATUS_NOT_FOUND = 0xC0000225;
    /** The referenced account is currently locked out */
    int NT_STATUS_ACCOUNT_LOCKED_OUT = 0xC0000234;
    /** The pathname does not traverse a DFS junction */
    int NT_STATUS_PATH_NOT_COVERED = 0xC0000257;
    /** The IO operation on the reparse point failed */
    int NT_STATUS_IO_REPARSE_TAG_NOT_HANDLED = 0xC0000279;

    /** Array of all NT status codes defined in this interface */
    int[] NT_STATUS_CODES = { NT_STATUS_SUCCESS, NT_STATUS_UNSUCCESSFUL, NT_STATUS_NOT_IMPLEMENTED, NT_STATUS_INVALID_INFO_CLASS,
            NT_STATUS_ACCESS_VIOLATION, NT_STATUS_INVALID_HANDLE, NT_STATUS_INVALID_PARAMETER, NT_STATUS_NO_SUCH_DEVICE,
            NT_STATUS_NO_SUCH_FILE, NT_STATUS_MORE_PROCESSING_REQUIRED, NT_STATUS_ACCESS_DENIED, NT_STATUS_BUFFER_TOO_SMALL,
            NT_STATUS_OBJECT_NAME_INVALID, NT_STATUS_OBJECT_NAME_NOT_FOUND, NT_STATUS_OBJECT_NAME_COLLISION, NT_STATUS_PORT_DISCONNECTED,
            NT_STATUS_OBJECT_PATH_INVALID, NT_STATUS_OBJECT_PATH_NOT_FOUND, NT_STATUS_OBJECT_PATH_SYNTAX_BAD, NT_STATUS_SHARING_VIOLATION,
            NT_STATUS_DELETE_PENDING, NT_STATUS_NO_LOGON_SERVERS, NT_STATUS_USER_EXISTS, NT_STATUS_NO_SUCH_USER, NT_STATUS_WRONG_PASSWORD,
            NT_STATUS_LOGON_FAILURE, NT_STATUS_ACCOUNT_RESTRICTION, NT_STATUS_INVALID_LOGON_HOURS, NT_STATUS_INVALID_WORKSTATION,
            NT_STATUS_PASSWORD_EXPIRED, NT_STATUS_ACCOUNT_DISABLED, NT_STATUS_NONE_MAPPED, NT_STATUS_INVALID_SID,
            NT_STATUS_INSTANCE_NOT_AVAILABLE, NT_STATUS_PIPE_NOT_AVAILABLE, NT_STATUS_INVALID_PIPE_STATE, NT_STATUS_PIPE_BUSY,
            NT_STATUS_PIPE_DISCONNECTED, NT_STATUS_PIPE_CLOSING, NT_STATUS_PIPE_LISTENING, NT_STATUS_FILE_IS_A_DIRECTORY,
            NT_STATUS_DUPLICATE_NAME, NT_STATUS_NETWORK_NAME_DELETED, NT_STATUS_NETWORK_ACCESS_DENIED, NT_STATUS_BAD_NETWORK_NAME,
            NT_STATUS_REQUEST_NOT_ACCEPTED, NT_STATUS_CANT_ACCESS_DOMAIN_INFO, NT_STATUS_NO_SUCH_DOMAIN, NT_STATUS_NOT_A_DIRECTORY,
            NT_STATUS_CANNOT_DELETE, NT_STATUS_INVALID_COMPUTER_NAME, NT_STATUS_PIPE_BROKEN, NT_STATUS_NO_SUCH_ALIAS,
            NT_STATUS_LOGON_TYPE_NOT_GRANTED, NT_STATUS_NO_TRUST_SAM_ACCOUNT, NT_STATUS_TRUSTED_DOMAIN_FAILURE,
            NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT, NT_STATUS_PASSWORD_MUST_CHANGE, NT_STATUS_NOT_FOUND, NT_STATUS_ACCOUNT_LOCKED_OUT,
            NT_STATUS_PATH_NOT_COVERED, NT_STATUS_IO_REPARSE_TAG_NOT_HANDLED, };

    /**
     * Array of NT status message strings corresponding to NT status codes.
     * These messages provide human-readable descriptions for various NT status values.
     */
    String[] NT_STATUS_MESSAGES = { "The operation completed successfully.", "A device attached to the system is not functioning.",
            "Incorrect function.", "The parameter is incorrect.", "Invalid access to memory location.", "The handle is invalid.",
            "The parameter is incorrect.", "The system cannot find the file specified.", "The system cannot find the file specified.",
            "More data is available.", "Access is denied.", "The data area passed to a system call is too small.",
            "The filename, directory name, or volume label syntax is incorrect.", "The system cannot find the file specified.",
            "Cannot create a file when that file already exists.", "The handle is invalid.", "The specified path is invalid.",
            "The system cannot find the path specified.", "The specified path is invalid.",
            "The process cannot access the file because it is being used by another process.", "Access is denied.",
            "There are currently no logon servers available to service the logon request.", "The specified user already exists.",
            "The specified user does not exist.", "The specified network password is not correct.",
            "Logon failure: unknown user name or bad password.", "Logon failure: user account restriction.",
            "Logon failure: account logon time restriction violation.", "Logon failure: user not allowed to log on to this computer.",
            "Logon failure: the specified account password has expired.", "Logon failure: account currently disabled.",
            "No mapping between account names and security IDs was done.", "The security ID structure is invalid.",
            "All pipe instances are busy.", "All pipe instances are busy.", "The pipe state is invalid.", "All pipe instances are busy.",
            "No process is on the other end of the pipe.", "The pipe is being closed.",
            "Waiting for a process to open the other end of the pipe.", "Access is denied.", "A duplicate name exists on the network.",
            "The specified network name is no longer available.", "Network access is denied.", "The network name cannot be found.",
            "No more connections can be made to this remote computer at this time because there are already as many connections as the computer can accept.",
            "Indicates a Windows NT Server could not be contacted or that objects within the domain are protected such that necessary information could not be retrieved.",
            "The specified domain did not exist.", "The directory name is invalid.", "Access is denied.",
            "The format of the specified computer name is invalid.", "The pipe has been ended.",
            "The specified local group does not exist.",
            "Logon failure: the user has not been granted the requested logon type at this computer.",
            "The SAM database on the Windows NT Server does not have a computer account for this workstation trust relationship.",
            "The trust relationship between the primary domain and the trusted domain failed.",
            "The account used is a Computer Account. Use your global user account or local user account to access this server.",
            "The user must change his password before he logs on the first time.", "NT_STATUS_NOT_FOUND",
            "The referenced account is currently locked out and may not be logged on to.",
            "The remote system is not reachable by the transport.", "NT_STATUS_IO_REPARSE_TAG_NOT_HANDLED", };
}
