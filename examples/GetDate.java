import java.util.Date;
import jcifs.smb.SmbFile;
import java.text.SimpleDateFormat;
import java.util.GregorianCalendar;

public class GetDate {

    public static void main( String argv[] ) throws Exception {
        SmbFile f = new SmbFile( argv[0] );
        Date d = new Date( f.lastModified() );
        SimpleDateFormat sdf = new SimpleDateFormat( "EEEE, MMMM d, yyyy h:mm:ss a" );
        sdf.setCalendar( new GregorianCalendar() );
        System.out.println( sdf.format( d ));
    }
}

