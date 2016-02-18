import jcifs.netbios.NbtAddress;
import jcifs.UniAddress;
import java.net.InetAddress;

public class Query {

    public static void main( String argv[] ) throws Exception {
        UniAddress ua;
        String cn;

        ua = UniAddress.getByName( argv[0] );

        cn = ua.firstCalledName();
        do {
            System.out.println( "calledName=" + cn );
        } while(( cn = ua.nextCalledName() ) != null );
    }
}
