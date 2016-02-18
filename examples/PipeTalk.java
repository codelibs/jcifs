import jcifs.smb.SmbNamedPipe;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.IOException;

public class PipeTalk {

    static class ReceiverThread extends Thread {
        InputStream in;
        byte[] buf = new byte[20];
        int n;

        ReceiverThread( InputStream in ) {
            this.in = in;
        }
        public void run() {
            try {
                while(( n = in.read( buf )) != -1 ) {
                    System.out.println( new String( buf, 0, n ));
                }
            } catch( IOException ioe ) {
                ioe.printStackTrace();
            }
        }
    }

    public static void main( String argv[] ) throws Exception {

        SmbNamedPipe pipe = new SmbNamedPipe( argv[0], SmbNamedPipe.PIPE_TYPE_RDWR );
        InputStream in = pipe.getNamedPipeInputStream();
        OutputStream out = pipe.getNamedPipeOutputStream();

        ReceiverThread rt = new ReceiverThread( in );
        rt.start();

        StringBuffer sb = new StringBuffer();
        String msg;
        int c;
        while(( c = System.in.read() ) != -1 ) {
            if( c == '\n' ) {
                msg = sb.toString();
                if( msg.startsWith( "exi" )) {
                    break;
                }
                System.out.println( sb.toString() );
                out.write( msg.getBytes() );
                sb.setLength( 0 );
            } else {
                sb.append( (char)c );
            }
        }
        in.close();
        out.close();
    }
}

