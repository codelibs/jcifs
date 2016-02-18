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
import jcifs.util.*;
import java.util.LinkedList;
import java.util.ListIterator;
import java.net.MalformedURLException;
import java.io.IOException;

public class T2Crawler {

    class Semaphore {
        private int value = 0;

        Semaphore() {value = 0;}
        Semaphore(int initial) {value = initial;}

        public synchronized void P() {
            value--;
            if (value < 0) {
                try {
                    wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }

        public synchronized void V() {
            value++;
            notify();
        }
    }

    class CrawlerThread extends Thread {
        LinkedList list;
        Semaphore sem;
        SmbFile dir;
        int depth;


        CrawlerThread( SmbFile dir, Semaphore sem, int depth ) {
            this.dir = dir;
            list = new LinkedList();
            list.add( dir );
            this.sem = sem;
            this.depth = depth;
        }

        public void run() {
            SmbFile d;
            SmbFile l[];

            while( list.isEmpty() == false ) {
                int i;
                d = (SmbFile)list.remove( 0 );
                try {
                    l = d.listFiles();

/* This is flawed. It decrements depth too agressively and causes the
 * thread to finish prematurely. I do not know of a way to fix this
 * because there is no concept of a stack here.
 */
                    depth--;
                    for( i = 0; i < l.length; i++ ) {
                        System.out.println( l[i] );
                    //  if( depth++ > 0 && l[i].isDirectory() && !l[i].isHidden() ) {
                        if( depth > 0 && l[i].isDirectory() ) {
                            list.add( l[i] );
                        }
                    }
                } catch( Exception e ) {
                    System.out.println( d );
                    e.printStackTrace();
                }
            }
            sem.V();
        }
    }

    T2Crawler( String dir, int numThreads, int depth ) throws Exception {
        SmbFile top = new SmbFile( dir );
        Semaphore sem = new Semaphore( numThreads );
        SmbFile[] l = null;
        int i = 0;

        try {
            l = top.listFiles();
            depth--;
            for( i = 0; i < l.length; i++ ) {
                try {
                    System.out.println( l[i] );
                    if( !l[i].isDirectory() || l[i].isHidden() ) {
                        continue;
                    }
                    if( depth > 0 ) {
                        sem.P();
                        (new CrawlerThread( l[i], sem, depth )).start();
                    }
                } catch( Exception e ) {
                    e.printStackTrace();
                }
            }
            for( i = 0; i < l.length; i++ ) {
                try {
                    l[i].canRead();
                } catch(Exception ex) {
                    System.err.println( l[i] );
                    ex.printStackTrace();
                }
            }
        } catch( Exception ex ) {
            System.err.println( l[i] );
            ex.printStackTrace();
        }
    }
    public static void main(String[] argv) throws Exception {
        if( argv.length < 3) {
            System.out.println( "$ java -Djcifs.properties=miallen.prp T2Crawler <dir> <num threads> <depth>");
            System.exit(1);
        }
        new T2Crawler( argv[0], Integer.parseInt( argv[1] ), Integer.parseInt( argv[2] ));
    }
}
