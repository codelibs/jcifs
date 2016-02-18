import jcifs.smb.SmbNamedPipe;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class WaitNamedPipe {

    public static void main( String[] argv ) throws Exception {

        if( argv.length < 2 ) {
            throw new IllegalArgumentException( "args: <smburl> <filedatatosend> <filetowriterecvdata>" );
        }

        byte[] b = new byte[65535];
        FileInputStream fin = new FileInputStream( argv[1] );
        FileOutputStream fos = new FileOutputStream( argv[2] );

        SmbNamedPipe pipe = new SmbNamedPipe( argv[0], SmbNamedPipe.PIPE_TYPE_RDWR );
        OutputStream out = pipe.getNamedPipeOutputStream();
        InputStream in = pipe.getNamedPipeInputStream();

        int n = fin.read( b );
        System.out.println( "writing " + n + " bytes" );
        out.write( b, 0, n );
        n = in.read(b);
        System.out.println( "read " + n + " bytes" );
        fos.write(b, 0, n );

        fin.close();
        fos.close();
        out.close();
    }
}
