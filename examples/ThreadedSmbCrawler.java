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

import jcifs.smb.SmbFile;
import java.util.LinkedList;
import java.util.ListIterator;
import java.net.MalformedURLException;
import java.io.IOException;

public class ThreadedSmbCrawler {

    static int workingThreads = 0;

    class DirEntry {
        SmbFile dir;
        int depth;

        DirEntry( SmbFile dir, int depth ) {
            this.dir = dir;
            this.depth = depth;
        }
    }

    class SmbCrawlerThread extends Thread {

        StringBuffer sb = new StringBuffer();

        public void run() {
            while( true ) {
                try {
                    DirEntry e;

                    synchronized( dirList ) {
                        while( dirList.isEmpty() ) {
//System.err.println( "workingThreads=" + workingThreads );
                            if( workingThreads == 0 ) {
                                return; // done
                            }
                            dirList.wait( 2000 );
                        }
                        e = (DirEntry)dirList.remove( 0 );
                        if( e.depth == 0 ) {
                            continue;
                        }
                        workingThreads++;
                    }

                    SmbFile[] l = e.dir.listFiles();

                    int n = maxDepth - e.depth;

                    for(int i = 0; l != null && i < l.length; i++ ) {
                        try {
                            sb.setLength( 0 );
                            for( int k = 0; k < n; k++ ) {
                                sb.append( "    " );
                            }
                            SmbFile d = l[i];
                            System.err.println( sb.append( d ));
                            if( d.isDirectory() ) {
                                synchronized( dirList ) {
                                    dirList.add( new DirEntry( d, e.depth - 1 ));
                                    dirList.notify();
                                }
                            }
                        } catch( IOException ioe ) {
                            ioe.printStackTrace();
                        }
                    }
                    synchronized( dirList ) {
                        workingThreads--;
                    }
                } catch( Exception x ) {
                    synchronized( dirList ) {
                        workingThreads--;
                    }
                    x.printStackTrace();
                }
            }
        }
    }

    LinkedList dirList;
    int maxDepth, numThreads;
    Thread[] threads;

    ThreadedSmbCrawler( String dir, int maxDepth, int numThreads ) throws Exception {
        this.maxDepth = maxDepth;
        this.numThreads = numThreads;
        threads = new Thread[numThreads];
        dirList = new LinkedList();
        dirList.add( new DirEntry( new SmbFile( dir ), maxDepth ));
    }

    long go() throws Exception {
        int i;
        long start = System.currentTimeMillis();

        for( i = 0; i < numThreads; i++ ) {
            threads[i] = new SmbCrawlerThread();
            threads[i].start();
        }
        for( i = 0; i < numThreads; i++ ) {
            threads[i].join();
        }

        return System.currentTimeMillis() - start;
    }

    public static void main(String[] argv) throws Exception {
        ThreadedSmbCrawler tsc;

        if( argv.length < 3 ) {
            System.err.println( "usage: ThreadedSmbCrawler dir depth numThreads" );
            System.exit( 1 );
        }

        tsc = new ThreadedSmbCrawler( argv[0], Integer.parseInt( argv[1] ), Integer.parseInt( argv[2] ));
        System.err.println( "Crawling Complete: " + (tsc.go() / 1000) + "sec" );
    }
}
