import java.util.LinkedList;
import java.util.ListIterator;
import java.net.MalformedURLException;
import java.io.IOException;
import jcifs.smb.*;

public class AclCrawler {

    int maxDepth;

    AclCrawler( int maxDepth ) {
        this.maxDepth = maxDepth;
    }

    void traverse( SmbFile f, int depth ) throws MalformedURLException, IOException {

        if( depth == 0 ) {
            return;
        }

        SmbFile[] l = f.listFiles();

        for(int i = 0; l != null && i < l.length; i++ ) {
            try {
                System.out.println( l[i] );
                ACE[] acl = l[i].getSecurity();
                for (int j = 0; j < acl.length; j++) {
                    System.out.print( acl[j] );
                    int a = acl[j].getAccessMask();
                    if ((a & 0xFF000000) != 0) {
                        if ((a & ACE.GENERIC_ALL) != 0) {
                            System.out.print( " GENERIC_ALL" );
                        }
                        if ((a & ACE.GENERIC_WRITE) != 0) {
                            System.out.print( " GENERIC_WRITE" );
                        }
                        if ((a & ACE.GENERIC_READ) != 0) {
                            System.out.print( " GENERIC_READ" );
                        }
                    }
                    System.out.println();
                }
                if( l[i].isDirectory() ) {
                    traverse( l[i], depth - 1 );
                }
            } catch( IOException ioe ) {
                ioe.printStackTrace();
            }
        }
    }

    public static void main(String[] argv) throws Exception {
        if (argv.length < 2) {
            System.err.println( "usage: AclCrawler <url> <depth>" );
            System.exit(1);
        }
        int depth = Integer.parseInt( argv[1] );
        AclCrawler sc = new AclCrawler( depth );
        sc.traverse( new SmbFile( argv[0] ), depth );
    }
}
