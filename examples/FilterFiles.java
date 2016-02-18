import jcifs.netbios.NbtAddress;
import jcifs.smb.*;
import java.util.Date;

public class FilterFiles {

    static class ShortFilenameFilter implements SmbFilenameFilter {
        public boolean accept( SmbFile dir, String name ) throws SmbException {
            return name.length() < 14;
        }
    }
    static class BigFileFilter implements SmbFileFilter {
        public boolean accept( SmbFile file ) throws SmbException {
            return file.length() > 0x1FFFFL;
        }
    }

    public static void main( String[] argv ) throws Exception {

        SmbFile file = new SmbFile( argv[0] );
        BigFileFilter filter = new BigFileFilter();
        ShortFilenameFilter sfilter = new ShortFilenameFilter();
        DosFileFilter everything = new DosFileFilter( "*", 0xFFFF );

        long t1 = System.currentTimeMillis();
        SmbFile[] files = file.listFiles( everything );
        long t2 = System.currentTimeMillis() - t1;

        for( int i = 0; i < files.length; i++ ) {
            System.out.print( " " + files[i].getName() );
        }
        System.out.println();
        System.out.println( files.length + " files in " + t2 + "ms" );
    }
}

