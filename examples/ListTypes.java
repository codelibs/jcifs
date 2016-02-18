import jcifs.netbios.NbtAddress;
import jcifs.smb.SmbFile;
import java.util.Date;

public class ListTypes {

    public static void main( String[] argv ) throws Exception {

        SmbFile file = new SmbFile( argv[0] );

        long t1 = System.currentTimeMillis();
        SmbFile[] files = file.listFiles();
        long t2 = System.currentTimeMillis() - t1;

        for( int i = 0; i < files.length; i++ ) {
            System.out.print( " " + files[i].getName() );
            switch(files[i].getType()) {
                case SmbFile.TYPE_FILESYSTEM:
                    System.out.println( "[TYPE_FILESYSTEM]" );
                    break;
                case SmbFile.TYPE_WORKGROUP:
                    System.out.println( "[TYPE_WORKGROUP]" );
                    break;
                case SmbFile.TYPE_SERVER:
                    System.out.println( "[TYPE_SERVER]" );
                    break;
                case SmbFile.TYPE_SHARE:
                    System.out.println( "[TYPE_SHARE]" );
                    break;
                case SmbFile.TYPE_NAMED_PIPE:
                    System.out.println( "[TYPE_NAMEDPIPE]" );
                    break;
                case SmbFile.TYPE_PRINTER:
                    System.out.println( "[TYPE_PRINTER]" );
                    break;
                case SmbFile.TYPE_COMM:
                    System.out.println( "[TYPE_COMM]" );
                    break;
            };
        }
        System.out.println( files.length + " files in " + t2 + "ms" );
    }
}
