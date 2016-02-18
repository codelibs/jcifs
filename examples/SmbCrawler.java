import jcifs.smb.SmbFile;
import java.util.LinkedList;
import java.util.ListIterator;
import java.net.MalformedURLException;
import java.io.IOException;

public class SmbCrawler {

    int maxDepth;

    SmbCrawler( int maxDepth ) {
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

    public static void main(String[] argv) throws Exception {
        int depth = Integer.parseInt( argv[1] );
        SmbCrawler sc = new SmbCrawler( depth );
        sc.traverse( new SmbFile( argv[0] ), depth );
    }
}
