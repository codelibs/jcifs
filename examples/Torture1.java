import java.io.*;
import jcifs.smb.*;
import java.util.*;

class Worker extends Thread {

    Torture1 t;
    Exception e;

    Worker( Torture1 t ) {
        this.t = t;
        e = null;
    }
    public void run() {
        try {
            t.torture();
        } catch( Exception e ) {
            this.e = e;
        }
    }
}

public class Torture1 {

    Properties prp;

    Torture1( Properties prp ) {
        this.prp = prp;
    }

    void compare( SmbFile f1, SmbFile f2 ) throws Exception {
        if( f1.isDirectory() && f2.isDirectory() ) {
            SmbFile[] dirents = f1.listFiles();
            SmbFile f;
            for( int i = 0; i < dirents.length; i++ ) {
                f = new SmbFile( f2, dirents[i].getName() );
                compare( dirents[i], f );
            }
        }
        if( f1.isDirectory() != f2.isDirectory() ) {
            System.err.println( "directory comparison failed" );
        }
        if( f1.isFile() != f2.isFile() ) {
            System.err.println( "file comparison failed" );
        }
        if( f1.getType() != f2.getType() ) {
            System.err.println( "type comparison failed" );
        }
        if( f1.getName().equals( f2.getName() ) == false ) {
            System.err.println( "name comparison failed: " + f1.getName() + " " + f2.getName() );
        }
        if( f1.length() != f2.length() ) {
            System.err.println( "length comparison failed: " + f1.length() + " " + f2.length() );
        }
    }

    void torture() throws Exception {
        String domain, username, password, server, share, directory;
        NtlmPasswordAuthentication ntlm;

        domain = prp.getProperty( "torture.dst.domain" );
        username = prp.getProperty( "torture.dst.username" );
        password = prp.getProperty( "torture.dst.password" );

        ntlm = new NtlmPasswordAuthentication( domain, username, password );

        server = prp.getProperty( "torture.dst.server" );
        share = prp.getProperty( "torture.dst.share" );
        directory = prp.getProperty( "torture.dst.directory" );

        SmbFile dst = new SmbFile( "smb://", ntlm );
        dst = new SmbFile( dst, server );
        dst = new SmbFile( dst, share );
        dst = new SmbFile( dst, directory );

        SmbFile src = new SmbFile( prp.getProperty( "torture.src.url" ));

System.err.println( src + " --> " + dst );
System.in.read();

        if( dst.exists() ) {
            dst.delete();
        }
        src.copyTo( dst );
System.err.println( "CopyTo done" );
System.in.read();
        compare( src, dst );
System.err.println( "Test Complete" );
    }

    public static void main( String[] argv ) throws Exception {
        Properties prp = new Properties();
        prp.load( new FileInputStream( "torture.prp" ));
        Torture1 t = new Torture1( prp );
        Worker w = new Worker( t );
        w.start();
        w.join();
        if( w.e != null ) {
            throw w.e;
        }
    }
}
