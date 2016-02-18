import java.util.LinkedList;
import java.util.ListIterator;
import java.net.MalformedURLException;
import java.io.IOException;

import jcifs.smb.*;

public class SidCrawler {

    static final byte[] SP = "                                              ".getBytes();

    static void printSpace(int count) {
        if (count > SP.length)
            count = SP.length;
        System.out.write(SP, 0, count);
    }

    int maxDepth;

    SidCrawler( int maxDepth ) {
        this.maxDepth = maxDepth;
    }

    void traverse( SmbFile f, int depth ) throws MalformedURLException, IOException {
        int indent = maxDepth - depth;

        if( depth == 0 ) {
            return;
        }

        SmbFile[] l = f.listFiles();

        for(int i = 0; l != null && i < l.length; i++ ) {
            try {
                printSpace(indent * 4);
                ACE[] acl = l[i].getSecurity(true);
                System.out.println( l[i] );
                for (int ai = 0; ai < acl.length; ai++) {
                    printSpace((indent + 1) * 4);
                    System.out.println("+ " + acl[ai].toString());
                }
                if( l[i].isDirectory() ) {
                    traverse( l[i], depth - 1 );
                }
            } catch( IOException ioe ) {
                System.out.println( l[i] + ":" );
                ioe.printStackTrace( System.out );
            }
        }
    }

    public static void main(String[] argv) throws Exception {
        if (argv.length < 2) {
            System.err.println("usage: SidCrawler <smburl> <depth>");
            return;
        }
        int depth = Integer.parseInt( argv[1] );
        SidCrawler sc = new SidCrawler( depth );
        sc.traverse( new SmbFile( argv[0] ), depth );
    }
}
