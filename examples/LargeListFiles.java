import jcifs.netbios.NbtAddress;
import jcifs.smb.*;
import java.util.Date;

public class LargeListFiles extends DosFileFilter {

    int count = 0;

    public LargeListFiles() {
        super("*", 0xFFFF);
    }
    public LargeListFiles(String wildcard, int attributes) {
        super(wildcard, attributes);
    }

    public boolean accept(SmbFile file) throws SmbException {
        System.out.print( " " + file.getName() );
        count++;
        return false; /* file processed here, tell listFiles() to discard */
    }

    public static void main( String[] argv ) throws Exception {
        if (argv.length < 1) {
            System.err.println("usage: LargeListFiles <smburl>\n");
            System.exit(1);
        }

        SmbFile file = new SmbFile( argv[0] );
        LargeListFiles llf = new LargeListFiles();

        long t1 = System.currentTimeMillis();
        file.listFiles(llf);
        long t2 = System.currentTimeMillis() - t1;

        System.out.println();
        System.out.println( llf.count + " files in " + t2 + "ms" );
    }
}

