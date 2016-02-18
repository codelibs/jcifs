import jcifs.smb.SmbNamedPipe;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.IOException;

public class PeekNamedPipe {

    static class ReceiverThread extends Thread {
        InputStream in;
        byte[] buf = new byte[20];
        int n;

        ReceiverThread( InputStream in ) {
            this.in = in;
        }
        public void run() {
            try {
                while( true ) {
                    while(( n = in.available() ) == 0 ) {
                        System.out.println( "0 available" );
                        sleep( 3000 );
                    }
                    System.out.println( n + " available" );

                    if(( n = in.read( buf )) == -1 ) {
                        break;
                    }
                    System.out.println( new String( buf, 0, n ));
                }
            } catch( Exception e ) {
                e.printStackTrace();
            }
            System.out.println( "run finished" );
        }
    }

    public static void main( String[] argv ) throws Exception {
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

