import jcifs.smb.SmbFile;
import java.util.LinkedList;
import java.util.ListIterator;
import java.net.MalformedURLException;
import java.io.IOException;

public class CrawlTest extends Thread {

    SmbFile f;
    int maxDepth;

    CrawlTest( SmbFile f, int maxDepth ) {
        this.f = f;
        this.maxDepth = maxDepth;
    }

    void traverse( SmbFile f, int depth ) throws MalformedURLException, IOException {

        if( depth == 0 ) {
            return;
        }

        SmbFile[] l = f.listFiles();

        for(int i = 0; l != null && i < l.length; i++ ) {
            try {
                for( int j = maxDepth - depth; j > 0; j-- ) {
                    System.out.print( "    " );
                }
                System.out.println( l[i] + " " + l[i].exists() );
                if( l[i].isDirectory() ) {
                    traverse( l[i], depth - 1 );
                }
            } catch( IOException ioe ) {
                System.out.println( l[i] + ":" );
                ioe.printStackTrace( System.out );
            }
        }
    }

    public void run() {
        try {
            traverse( f, maxDepth );
        } catch( Exception ex ) {
            ex.printStackTrace();
        }
    }

    public static void main(String[] argv) throws Exception {
        if (argv.length < 3) {
            System.err.println( "CrawlTest <url> <numthreads> <maxdepth>" );
            return;
        }

        SmbFile f = new SmbFile( argv[0] );
        int numThreads = Integer.parseInt( argv[1] );
        int maxDepth = Integer.parseInt( argv[2] );

        while (numThreads-- > 0 && System.in.read() == '\n') {
            CrawlTest sc = new CrawlTest( f, maxDepth );
            sc.start();
        }
    }
}
