import java.io.*;
import jcifs.smb.*;
import jcifs.util.Hexdump;
import java.util.*;

public class Torture2 extends Thread {

    SmbFile from, to;

    Torture2( String from, String to ) throws Exception {
        this.from = new SmbFile( from );
        this.to = new SmbFile( to );
    }

    public void run() {
        try {
            copyAndVerify();
        } catch( Exception e ) {
            e.printStackTrace();
        }
    }

    void compare( SmbFile f1, SmbFile f2 ) throws Exception {
//System.err.println( f1.getName() + " | " + f2.getName() );
try {
        if( f1.isDirectory() && f2.isDirectory() ) {
            SmbFile[] dirents = f1.listFiles();
            SmbFile f;
            for( int i = 0; i < dirents.length; i++ ) {
                f = new SmbFile( f2, dirents[i].getName() );
//System.err.println( f2 + " + " + dirents[i].getName() + " = " + f + ": isDirectory=" + f.isDirectory() );
                compare( dirents[i], f );
            }
        }
        if( f1.isDirectory() != f2.isDirectory() ) {
            System.err.println( "directory comparison failed: " + f1.getName() + ": " + f1.isDirectory() + " " + f2.isDirectory() );
        }
        if( f1.isFile() != f2.isFile() ) {
            System.err.println( "file comparison failed: " + f1.getName() + ": " + f1.isFile() + " " + f2.isFile() );
        }
        if( f1.getType() != f2.getType() ) {
            System.err.println( "type comparison failed: " + f1.getName() + " " + f2.getName() );
        }
        if( f1.getName().equals( f2.getName() ) == false ) {
            System.err.println( "name comparison failed: " + f1.getName() + " " + f2.getName() );
        }
        if( f1.length() != f2.length() ) {
            System.err.println( "length comparison failed: " + f1.getName() + ": " + f1.length() + " " + f2.length() );
        }
        if( f1.getAttributes() != f2.getAttributes() ) {
            System.err.println( "attribute comparison failed: " + f1.getName() + ": " + Hexdump.toHexString( f1.getAttributes(), 4 ) + " " + Hexdump.toHexString( f2.getAttributes(), 4 ));
        }
        if( Math.abs( f1.createTime() - f2.createTime() ) > 1000 ) {
            System.err.println( "create time comparison failed: " + f1.getName() + ": " + f1.createTime() + " " + f2.createTime() );
        }
        if( Math.abs( f1.lastModified() - f2.lastModified() ) > 1000 ) {
            System.err.println( "last modified comparison failed: " + f1.getName() + ": " + f1.lastModified() + " " + f2.lastModified() );
        }
} catch( Exception x ) {
    System.err.println( "Exception comparing: " + f1 + " | " + f2 );
    x.printStackTrace();
}
    }

    void copyAndVerify() throws Exception {
        from.copyTo( to );
        compare( from, to );
    }

    public static void main( String[] argv ) throws Exception {
        Properties prp;
        Torture2[] threads;
        String from, to;
        int i;

        if( argv.length < 1 ) {
            System.err.println( "Torture2 <properties file>" );
            System.exit( 1 );
        }

        prp = new Properties();
        prp.load( new FileInputStream( argv[0] ));

        threads = new Torture2[10];

        for( i = 0; i < 10; i++ ) {
            from = prp.getProperty( "thread." + i + ".from.url" );
            to = prp.getProperty( "thread." + i + ".to.url" );
            if( from == null || to == null ) {
                break;
            }
            threads[i] = new Torture2( from, to );
            threads[i].start();
            Thread.sleep( 12345 );
        }
        while( i-- > 0 ) {
            threads[i].join();
        }
        System.err.println( "Test complete" );
    }
}

