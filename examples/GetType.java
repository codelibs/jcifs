import jcifs.netbios.NbtAddress;
import jcifs.smb.SmbFile;
import java.util.Date;

public class GetType {

    static final String[] types = { "TYPE_FILESYSTEM", "TYPE_WORKGROUP",
        "TYPE_SERVER", "TYPE_SHARE", "TYPE_NAMED_PIPE", "TYPE_PRINTER", "TYPE_COMM" };

    public static void main( String[] argv ) throws Exception {

        SmbFile file = new SmbFile( argv[0] );
        int type;

        switch( file.getType() ) {
            case SmbFile.TYPE_FILESYSTEM:
                type = 0;
                break;
            case SmbFile.TYPE_WORKGROUP:
                type = 1;
                break;
            case SmbFile.TYPE_SERVER:
                type = 2;
                break;
            case SmbFile.TYPE_SHARE:
                type = 3;
                break;
            case SmbFile.TYPE_NAMED_PIPE:
                type = 4;
                break;
            case SmbFile.TYPE_PRINTER:
                type = 5;
                break;
            case SmbFile.TYPE_COMM:
                type = 6;
                break;
            default:
                throw new RuntimeException( "Unknown service type: " + file.getType() );
        }
        System.out.println( types[type] );
        System.out.println();

        long t1 = System.currentTimeMillis();
        String[] files = file.list();
        long t2 = System.currentTimeMillis() - t1;

        for( int i = 0; i < files.length; i++ ) {
            System.out.print( " " + files[i] );
        }
        System.out.println();
        System.out.println( files.length + " files in " + t2 + "ms" );
    }
}
