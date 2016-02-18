/* examples for the jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* createf.c - Create a file with the CreateFile call.
 */


#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>

#define hexstrtoui(s) ((int)strtoul((s), NULL, 16))

int
main(int argc, char *argv[])
{
    int i;
    int desiredAccess, shareMode, disposition, flags, bufferSize, bytesRead;
    char *target, *buf;
    HANDLE h, inFile, outFile;

    inFile = NULL;
    outFile = NULL;
    desiredAccess = GENERIC_READ;
    shareMode = 0;
    disposition = CREATE_ALWAYS;
    flags = FILE_ATTRIBUTE_NORMAL;
    bufferSize = 65535;

    if (argc == 1 || argv[1][1] == '\?') {

        /* dwDesiredAccess
         */
        printf("dwDesiredAccess\r\n");
        printf("  0x%08x GENERIC_READ\r\n", GENERIC_READ);
        printf("  0x%08x GENERIC_WRITE\r\n", GENERIC_WRITE);
        printf("  0x%08x DELETE\r\n", DELETE);
        printf("  0x%08x READ_CONTROL\r\n", READ_CONTROL);
        printf("  0x%08x WRITE_DAC\r\n", WRITE_DAC);
        printf("  0x%08x WRITE_OWNER\r\n", WRITE_OWNER);
        printf("  0x%08x SYNCHRONIZE\r\n", SYNCHRONIZE);
        printf("  0x%08x STANDARD_RIGHTS_REQUIRED\r\n", STANDARD_RIGHTS_REQUIRED);
        printf("  0x%08x STANDARD_RIGHTS_READ\r\n", STANDARD_RIGHTS_READ);
        printf("  0x%08x STANDARD_RIGHTS_WRITE\r\n", STANDARD_RIGHTS_WRITE);
        printf("  0x%08x STANDARD_RIGHTS_EXECUTE\r\n", STANDARD_RIGHTS_EXECUTE);
        printf("  0x%08x STANDARD_RIGHTS_ALL\r\n", STANDARD_RIGHTS_ALL);
        printf("  0x%08x SPECIFIC_RIGHTS_ALL\r\n", SPECIFIC_RIGHTS_ALL);
        printf("  0x%08x ACCESS_SYSTEM_SECURITY\r\n", ACCESS_SYSTEM_SECURITY);
        printf("  0x%08x MAXIMUM_ALLOWED\r\n", MAXIMUM_ALLOWED);
        printf("  0x%08x GENERIC_EXECUTE\r\n", GENERIC_EXECUTE);
        printf("  0x%08x GENERIC_ALL\r\n", GENERIC_ALL);
        /* dwShareMode
         */
        printf("dwShareMode\n");
        printf("  0x%08x FILE_SHARE_DELETE\r\n", FILE_SHARE_DELETE);
        printf("  0x%08x FILE_SHARE_READ\r\n", FILE_SHARE_READ);
        printf("  0x%08x FILE_SHARE_WRITE\r\n", FILE_SHARE_WRITE);
        printf("  0x%08x the file cannot be shared\r\n", 0);
        /* dwCreateDisposition
         */
        printf("dwCreateDisposition\r\n");
        printf("  0x%08x CREATE_NEW\r\n", CREATE_NEW);
        printf("  0x%08x CREATE_ALWAYS\r\n", CREATE_ALWAYS);
        printf("  0x%08x OPEN_EXISTING\r\n", OPEN_EXISTING);
        printf("  0x%08x OPEN_ALWAYS\r\n", OPEN_ALWAYS);
        printf("  0x%08x TRUNCATE_EXISTING\r\n", TRUNCATE_EXISTING);
        /* dwFlagsAndAttributes
         */
        printf("dwFlagsAndAttributes\r\n");
        printf("  0x%08x FILE_ATTRIBUTE_ARCHIVE\r\n", FILE_ATTRIBUTE_ARCHIVE);
        printf("  0x%08x FILE_ATTRIBUTE_ENCRYPTED\r\n", FILE_ATTRIBUTE_ENCRYPTED);
        printf("  0x%08x FILE_ATTRIBUTE_HIDDEN\r\n", FILE_ATTRIBUTE_HIDDEN);
        printf("  0x%08x FILE_ATTRIBUTE_NORMAL\r\n", FILE_ATTRIBUTE_NORMAL);
        printf("  0x%08x FILE_ATTRIBUTE_NOT_CONTENT_INDEXED\r\n", FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
        printf("  0x%08x FILE_ATTRIBUTE_OFFLINE\r\n", FILE_ATTRIBUTE_OFFLINE);
        printf("  0x%08x FILE_ATTRIBUTE_READONLY\r\n", FILE_ATTRIBUTE_READONLY);
        printf("  0x%08x FILE_ATTRIBUTE_SYSTEM\r\n", FILE_ATTRIBUTE_SYSTEM);
        printf("  0x%08x FILE_ATTRIBUTE_TEMPORARY\r\n", FILE_ATTRIBUTE_TEMPORARY);
        
        printf("  0x%08x FILE_FLAG_WRITE_THROUGH\r\n", FILE_FLAG_WRITE_THROUGH);
        printf("  0x%08x FILE_FLAG_OVERLAPPED\r\n", FILE_FLAG_OVERLAPPED);
        printf("  0x%08x FILE_FLAG_NO_BUFFERING\r\n", FILE_FLAG_NO_BUFFERING);
        printf("  0x%08x FILE_FLAG_RANDOM_ACCESS\r\n", FILE_FLAG_RANDOM_ACCESS);
        printf("  0x%08x FILE_FLAG_SEQUENTIAL_SCAN\r\n", FILE_FLAG_SEQUENTIAL_SCAN);
        printf("  0x%08x FILE_FLAG_DELETE_ON_CLOSE\r\n", FILE_FLAG_DELETE_ON_CLOSE);
        printf("  0x%08x FILE_FLAG_BACKUP_SEMANTICS\r\n", FILE_FLAG_BACKUP_SEMANTICS);
        printf("  0x%08x FILE_FLAG_POSIX_SEMANTICS\r\n", FILE_FLAG_POSIX_SEMANTICS);
        
        printf("  0x%08x FILE_FLAG_OPEN_REPARSE_POINT\r\n", FILE_FLAG_OPEN_REPARSE_POINT);
        printf("  0x%08x FILE_FLAG_OPEN_NO_RECALL\r\n", FILE_FLAG_OPEN_NO_RECALL);
        printf("  0x%08x SECURITY_ANONYMOUS\r\n", SECURITY_ANONYMOUS);
        printf("  0x%08x SECURITY_IDENTIFICATION\r\n", SECURITY_IDENTIFICATION);
        printf("  0x%08x SECURITY_IMPERSONATION\r\n", SECURITY_IMPERSONATION);
        printf("  0x%08x SECURITY_DELEGATION\r\n", SECURITY_DELEGATION);
        printf("  0x%08x SECURITY_CONTEXT_TRACKING\r\n", SECURITY_CONTEXT_TRACKING);
        printf("  0x%08x SECURITY_EFFECTIVE_ONLY\r\n", SECURITY_EFFECTIVE_ONLY);

        printf("defaults\r\n");
        printf("  dwDesiredAccess      = GENERIC_READ\r\n");
        printf("  dwShareMode          = FILE_SHARE_READ\r\n");
        printf("  dwCreateDisposition  = CREATE_ALWAYS\r\n");
        printf("  dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL\r\n");
        printf("  inFile               = none\r\n");
        printf("  outFile              = none\r\n");
        printf("  bufferSize           = 65535\r\n");

        printf("\r\ncreatef \\\\server\\share\\path /A access /S share /D disposition /F flags /I inFile /O outFile /B bufferSize\r\n");

        return 0;
    }

    if(argv[1][0] != '\\' && argv[1][1] != '\\') {
        printf("Error: must specify target\r\n");
    }
    target = argv[1];
    for(i = 2; i < argc; i++) {
        if(argv[i][0] != '/') {
            printf("Error: invalid switch\r\n");
        }
        errno = 0;
        switch(argv[i++][1]) {
            case 'A':
                desiredAccess = hexstrtoui(&argv[i][2]);
                break;
            case 'S':
                shareMode = hexstrtoui(argv[i]);
                break;
            case 'D':
                disposition = hexstrtoui(argv[i]);
                break;
            case 'F':
                flags = hexstrtoui(argv[i]);
                break;
            case 'I':
                inFile = CreateFile(argv[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); 
                if(inFile == INVALID_HANDLE_VALUE) {
                    printf("Error: cannot open inFile: %s\r\n", argv[i]);
                    CloseHandle(outFile);
                    return 0;
                }
                break;
            case 'O':
                outFile = CreateFile(argv[i], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); 
                if(outFile == INVALID_HANDLE_VALUE) {
                    printf("Error: cannot open outFile: %s\r\n", argv[i]);
                    CloseHandle(inFile);
                    return 0;
                }
                break;
            default:
                printf("Error: no such option\r\n");
                return 0;
        }
        if(errno) {
            printf("Error: %s\r\n", strerror(errno));
            return 0;
        }
    }

    buf = malloc(bufferSize);
    if(buf == NULL) {
        printf("Error: failed to allocate buffer\r\n");
        CloseHandle(inFile);
        CloseHandle(outFile);
        return 0;
    }
    h = CreateFile(target, desiredAccess, shareMode, NULL, disposition, flags, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("Error: CreateFile operation failed: %u\r\n", GetLastError());
        CloseHandle(inFile);
        CloseHandle(outFile);
        return 0;
    }
    if(inFile != NULL || outFile != NULL) {
        /* need to do reading or writing of some sort on the pipe */

        if(inFile == NULL) {
            inFile = h;
        }
        if(outFile == NULL) {
            outFile = h;
        }
        while(ReadFile(inFile, buf, bufferSize, &bytesRead, NULL) > 0) {
            WriteFile(outFile, buf, bytesRead, &bytesRead, NULL);
        }
    }
    printf("Success: operation performed successfully\r\n");
    CloseHandle(inFile);
    CloseHandle(outFile);
    CloseHandle(h);
    return 1;
}

