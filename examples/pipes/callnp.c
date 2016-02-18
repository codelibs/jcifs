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

/* callnp.c - Call a Named Pipe
 */

#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>

int
hexstrtoi(const char *str)
{
    int i;
    for (i = 0; str[i] != '\0'; i++) {
        if (str[i] != 'x' && (str[i] < 48 || str[i] > 57)) {
            errno = 1;
            return 0;
        }
    }
    return (int)strtol(str, NULL, 16);
}

int
main(int argc, char *argv[])
{
    int i;
    int bufferSize, timeout, bytesRead;
    char *target, *send_buf, *recv_buf;
    HANDLE inFile, outFile;

    inFile = NULL;
    outFile = NULL;
    bufferSize = 65535;
    bytesRead = 0;

    if (argc == 1 || argv[1][1] == '\?') {
        printf("defaults\r\n");
        printf("  inFile     = <none>\r\n");
        printf("  outFile    = <none>\r\n");
        printf("  bufferSize = 65535\r\n");

        printf("\r\ncallnp \\\\server\\pipe\\name /I inFile /O outFile /B bufferSize\r\n");

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
            case 'I':
                inFile = CreateFile(argv[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); 
                if(outFile == INVALID_HANDLE_VALUE) {
                    printf("Error: cannot open inFile: %s\r\n", argv[i]);
                    return 0;
                }
                break;
            case 'O':
                outFile = CreateFile(argv[i], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); 
                if(outFile == INVALID_HANDLE_VALUE) {
                    printf("Error: cannot open outFile: %s\r\n", argv[i]);
                    return 0;
                }
                break;
            case 'B':
                bufferSize = atoi(argv[i]);
                break;
            default:
                printf("Error: no such option\r\n");
                return 0;
        }
        if(errno) {
            printf("Error: values must be in hex.\r\n");
            return 0;
        }
    }
    send_buf = malloc(bufferSize);
    recv_buf = malloc(bufferSize);
    if(send_buf == NULL || recv_buf == NULL) {
        printf("Error: failed to allocate buffers\r\n");
        return 0;
    }
    if(inFile != NULL && ReadFile(inFile, send_buf, bufferSize, &bytesRead, NULL) == 0) {
        printf("Error: failed to read from inFile\r\n");
        return 0;
    }
    if (WaitNamedPipe(target, NMPWAIT_WAIT_FOREVER) == 0) {
        printf("Error: WaitNamedPipe operation failed: %u\r\n", GetLastError());
        return 0;
    }
    if (CallNamedPipe(target, send_buf, bytesRead, recv_buf, bufferSize, &bytesRead, NMPWAIT_WAIT_FOREVER) == 0) {
        printf("Error: CallNamedPipe operation failed: %u\r\n", GetLastError());
        return 0;
    }
    if(outFile != NULL && WriteFile(outFile, recv_buf, bytesRead, &bytesRead, NULL) == 0) {
        printf("Error: failed to write to outFile\r\n");
    }
    printf("Success: operation performed successfully\r\n");
    return 1;
}

