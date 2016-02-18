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

/* createnp.c - Create a named pipe with CreateNamedPipe.
 */

#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>

#define hexstrtoui(s) ((int)strtoul((s), NULL, 16))

int
main(int argc, char *argv[])
{
    int i;
    int openMode, pipeMode, bufferSize, defaultTimeout, bytesRead;
    char *target, *buf;
    HANDLE h, inFile, outFile;

    inFile = NULL;
    outFile = NULL;
    openMode = PIPE_ACCESS_DUPLEX;
    pipeMode = PIPE_TYPE_BYTE | PIPE_WAIT;
    bufferSize = 65535;

    if (argc == 1 || argv[1][1] == '\?') {

        /* dwOpenMode
         */
        printf("dwOpenMode\r\n");
        printf("  0x%08x PIPE_ACCESS_DUPLEX\r\n", PIPE_ACCESS_DUPLEX);
        printf("  0x%08x PIPE_ACCESS_INBOUND\r\n", PIPE_ACCESS_INBOUND);
        printf("  0x%08x PIPE_ACCESS_OUTBOUND\r\n", PIPE_ACCESS_OUTBOUND);
        printf("  0x%08x FILE_FLAG_WRITE_THROUGH\r\n", FILE_FLAG_WRITE_THROUGH);
        printf("  0x%08x FILE_FLAG_OVERLAPPED\r\n", FILE_FLAG_OVERLAPPED);
        printf("  0x%08x WRITE_DAC\r\n", WRITE_DAC);
        printf("  0x%08x WRITE_OWNER\r\n", WRITE_OWNER);
        printf("  0x%08x ACCESS_SYSTEM_SECURITY\r\n", ACCESS_SYSTEM_SECURITY);
        /* dwPipeMode
         */
        printf("dwPipeMode\r\n");
        printf("  0x%08x PIPE_TYPE_BYTE\r\n", PIPE_TYPE_BYTE);
        printf("  0x%08x PIPE_TYPE_MESSAGE\r\n", PIPE_TYPE_MESSAGE);
        printf("  0x%08x PIPE_READMODE_BYTE\r\n", PIPE_READMODE_BYTE);
        printf("  0x%08x PIPE_READMODE_MESSAGE\r\n", PIPE_READMODE_MESSAGE);
        printf("  0x%08x PIPE_WAIT\r\n", PIPE_WAIT);
        printf("  0x%08x PIPE_NOWAIT\r\n", PIPE_NOWAIT);

        printf("defaults\r\n");
        printf("  inFile     = <read from pipe input>\r\n");
        printf("  outFile    = <write to pipe output>\r\n");
        printf("  dwOpenMode = PIPE_ACCESS_DUPLEX\r\n");
        printf("  dwPipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT\r\n");
        printf("  bufferSize = 65535\r\n");

        printf("\r\ncreatenp \\\\.\\pipe\\name /I inFile /O outFile /M mode /P pmode /B bufferSize\r\n");

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
            case 'M':
                openMode = hexstrtoui(argv[i]);
                break;
            case 'P':
                pipeMode = hexstrtoui(argv[i]);
                break;
            case 'B':
                bufferSize = atoi(argv[i]);
                break;
            default:
                printf("Error: no such option\r\n");
                CloseHandle(inFile);
                CloseHandle(outFile);
                return 0;
        }
        if(errno) {
            printf("Error: values must be in hex.\r\n");
            CloseHandle(inFile);
            CloseHandle(outFile);
            return 0;
        }
    }
    h = CreateNamedPipe(target, openMode, pipeMode, 1, bufferSize, bufferSize, NMPWAIT_WAIT_FOREVER, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("Error: CreateNamedPipe operation failed: %u\r\n", GetLastError());
        CloseHandle(inFile);
        CloseHandle(outFile);
        return 0;
    }
    if(ConnectNamedPipe(h, NULL) == 0 && GetLastError() != ERROR_PIPE_CONNECTED) {
        printf("Error: ConnectNamedPipe operation failed: %u\r\n", GetLastError());
        CloseHandle(inFile);
        CloseHandle(outFile);
        CloseHandle(h);
        return 0;
    }
    buf = malloc(bufferSize);
    if(buf == NULL) {
        printf("Error: failed to allocate buffer\r\n");
        CloseHandle(inFile);
        CloseHandle(outFile);
        DisconnectNamedPipe(h);
        CloseHandle(h);
        return 0;
    }
    if(inFile == NULL) {
        inFile = h;
    }
    if(outFile == NULL) {
        outFile = h;
    }
    while(ReadFile(inFile, buf, bufferSize, &bytesRead, NULL) > 0) {
        WriteFile(outFile, buf, bytesRead, &bytesRead, NULL);
    }
    printf("Success: operation performed successfully\r\n");
    CloseHandle(inFile);
    CloseHandle(outFile);
    DisconnectNamedPipe(h);
    CloseHandle(h);
    return 1;
}

