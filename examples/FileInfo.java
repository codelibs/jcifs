import java.util.*;
import java.text.*;
import java.net.*;
import jcifs.smb.*;

public class FileInfo {

    static final String TYPES[] = {
        "TYPE_COMM",
        "TYPE_FILESYSTEM",
        "TYPE_NAMED_PIPE",
        "TYPE_PRINTER",
        "TYPE_SERVER",
        "TYPE_SHARE",
        "TYPE_WORKGROUP"
    };

    public static void main( String argv[] ) throws Exception {
        int i, start, end;;
        SimpleDateFormat sdf = new SimpleDateFormat( "MM/dd/yy hh:mm:ss a" );
        GregorianCalendar cal = new GregorianCalendar();
        SmbFile f;

        if( argv.length < 2 ) {
            throw new IllegalArgumentException( "usage: FileInfo <url> <opindex>" );
        }

        if( argv.length == 3 ) {
            SmbFile tmp = new SmbFile( argv[0] );
            f = new SmbFile( tmp.toString(), argv[1] );
            start = Integer.parseInt( argv[2] );
        } else {
            f = new SmbFile( argv[0] );
            start = Integer.parseInt( argv[1] );
        }

        sdf.setCalendar( cal );

        i = end = start;
        do {
            switch( i ) {
                case 0:
                    System.out.println( "        toString: " + f.toString() );
                    break;
                case 1:
                    System.out.println( "           toURL: " + f.toURL() );
                    break;
                case 2:
                    System.out.println( "         getName: " + f.getName() );
                    break;
                case 3:
                    System.out.println( "          length: " + f.length() );
                    break;
                case 4:
                    System.out.println( " getLastModified: " + sdf.format( new Date( f.getLastModified() )));
                    break;
                case 5:
                    System.out.println( "        isHidden: " + f.isHidden() );
                    break;
                case 6:
                    System.out.println( "          isFile: " + f.isFile() );
                    break;
                case 7:
                    System.out.println( "     isDirectory: " + f.isDirectory() );
                    break;
                case 8:
                    System.out.println( "        hashCode: " + f.hashCode() );
                    break;
                case 9:
                    System.out.println( "      getUncPath: " + f.getUncPath() );
                    break;
                case 10:
                    System.out.println( "         getType: " + TYPES[f.getType()] );
                    break;
                case 11:
                    System.out.println( "        getShare: " + f.getShare() );
                    break;
                case 12:
                    System.out.println( "       getServer: " + f.getServer() );
                    break;
                case 13:
                    System.out.println( "         getPath: " + f.getPath() );
                    break;
                case 14:
                    System.out.println( "       getParent: " + f.getParent() );
                    break;
                case 15:
                    System.out.println( "    lastModified: " + sdf.format( new Date( f.lastModified() )));
                    break;
                case 16:
                    System.out.println( "getDiskFreeSpace: " + f.getDiskFreeSpace() );
                    break;
                case 17:
                    System.out.println( "         getDate: " + sdf.format( new Date( f.getDate() )));
                    break;
                case 18:
                    System.out.println( "getContentLength: " + f.getContentLength() );
                    break;
                case 19:
                    System.out.println( "getCanonicalPath: " + f.getCanonicalPath() );
                    break;
                case 20:
                    System.out.println( "          exists: " + f.exists() );
                    break;
                case 21:
                    System.out.println( "         canRead: " + f.canRead() );
                    break;
                case 22:
                    System.out.println( "        canWrite: " + f.canWrite() );
                    break;
                case 23:
                    ACE[] security = f.getSecurity(true);
                    System.out.println( "        Security:" );
                    for (int ai = 0; ai < security.length; ai++) {
                        System.out.println(security[ai].toString());
                    }
                    System.out.println("       Share Perm:");
                    security = f.getShareSecurity(true);
                    for (int ai = 0; ai < security.length; ai++) {
                        System.out.println(security[ai].toString());
                    }
                    break;
                case 24:
                    System.out.println( "      getDfsPath: " + f.getDfsPath() );
                    break;
            }
            i++;
            if( i == 25 ) {
                i = 0;
            }
        } while( i != end );
    }
}

