import java.io.*;
import jcifs.smb.*;
import jcifs.util.*;

public class TestUnicode {
    static SmbFile dir;

    public static void mkobj( String name ) throws Exception {
        int r = (int)(Math.random() * 100.0);
        if( r < 50 ) {
            SmbFile d = new SmbFile( dir.getParent(), dir.getName() + "/" + name );
            d.mkdir();
            if( r < 15 ) {
                dir = d;
            }
        } else {
            SmbFileOutputStream out = new SmbFileOutputStream( dir.getParent() + "/" + dir.getName() + "/" + name );
            out.close();
        }
    }

    public static void main( String argv[] ) throws Exception {
        if( argv.length < 1 ) {
            throw new IllegalArgumentException( "Must provide path to directory in which to run test" );
        }
        FileInputStream in = new FileInputStream( "data" );
        byte[] b = new byte[4096];
        int n = in.read( b );
        String data = new String( b, 0, n, "UTF-8" );
        char[] d = data.toCharArray();

        dir = new SmbFile( argv[0] + "/TestUnicode" );
        try {
            dir.delete();
        } catch( SmbException se ) {
            se.printStackTrace();
        }
        dir.mkdir();

        int i, s, max = 8;
        for( i = s = 0; i < d.length; i++ ) {
            switch (d[i]) {
                case '"': case '/': case '\\': case '[': case ']':
                case ':': case '|': case '<': case '>': case '=':
                case ';': case ',': case '*': case '?': case '\n':
                    d[i] = '_';
            }
            if(Character.isWhitespace( d[i] )) {
                if( i == s ) {
                    s++;
                }
                if( i > (s + max)) {
                    String name = new String( d, s, i - s );
                    mkobj( name );
                    s = i + 1;
                }
            }
        }
    }
}
