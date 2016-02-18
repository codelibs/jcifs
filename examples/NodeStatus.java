import jcifs.netbios.NbtAddress;

public class NodeStatus {

    public static void main( String argv[] ) throws Exception {
        NbtAddress[] addrs = NbtAddress.getAllByAddress( argv[0] );
        for( int i = 0; i < addrs.length; i++ ) {
            System.out.println( addrs[i] );
        }
    }
}
