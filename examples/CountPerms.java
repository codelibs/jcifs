import jcifs.smb.SmbFile;
import java.util.LinkedList;
import java.util.ListIterator;
import java.net.MalformedURLException;
import java.io.IOException;
import jcifs.util.Hexdump;

public class CountPerms {

    int maxDepth;
    int numFiles;
    int numDirectories;
    int numMeta;
    int numMetaWithArch;

    int[] permissionCounts = new int[16];

    String[] permissionNames = {
        "Read Only",
        "Hidden",
        "System",
        "Volume ID",
        "Directory",
        "Archive",
        "Device",
        "Normal",
        "Temporary",
        "Sparse",
        "Reparse Point",
        "Compressed",
        "Offline",
        "Content Indexed",
        "Encrypted",
        "Unknown"
    };

    CountPerms( int maxDepth ) {
        this.maxDepth = maxDepth;
    }

    void traverse( SmbFile f, int depth ) throws MalformedURLException, IOException {

        if( depth == 0 ) {
            return;
        }

        SmbFile[] l = f.listFiles();

        for(int i = 0; l != null && i < l.length; i++ ) {
            try {
                int attrs = l[i].getAttributes();

                if(( attrs & 0x7FEE ) != 0) {
                    if(( attrs & 0x7FCE ) != 0) {
                        numMeta++;
                    }
                    numMetaWithArch++;
                }
                for (int b = 0; b < 16; b++) {
                    if(( attrs & (1 << b)) != 0 ) {
                        permissionCounts[b]++;
                    }
                }

                System.out.print( Hexdump.toHexString( l[i].getAttributes(), 4 ) + ": " );
                for( int j = maxDepth - depth; j > 0; j-- ) {
                    System.out.print( "    " );
                }
                System.out.println( l[i].getName()  );
                if( l[i].isDirectory() ) {
                    traverse( l[i], depth - 1 );
                }

                if(( attrs & SmbFile.ATTR_DIRECTORY ) != 0 ) {
                    numDirectories++;
                } else {
                    numFiles++;
                }
            } catch( IOException ioe ) {
                System.out.println( l[i] + ": " + ioe.getMessage() );
            }
        }
    }

    void run( String url ) throws Exception {
        traverse( new SmbFile( url ), maxDepth );

        for (int p = 0; p < 16; p++) {
            int len = 15 - permissionNames[p].length();
            while( len > 0 ) {
                System.out.print( " " );
                len--;
            }
            System.out.println( permissionNames[p] + ": " + permissionCounts[p] );
        }
        System.out.println( "            num files: " + numFiles );
        System.out.println( "      num directories: " + numDirectories );
        System.out.println( "             num both: " + (numFiles + numDirectories) );
        System.out.println( "             meta req: " + numMeta );
        System.out.println( "meta (incl. arch) req: " + numMetaWithArch );
    }

    public static void main(String[] argv) throws Exception {

        if( argv.length < 2 ) {
            System.err.println( "usage: CountPerms <dir> <maxdepth>" );
            System.exit(1);
        }

        int depth = Integer.parseInt( argv[1] );
        CountPerms cp = new CountPerms( depth );
        cp.run( argv[0] );
    }
}
