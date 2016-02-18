import java.util.Date;
import jcifs.smb.*;
import java.io.*;

public class TestSmbURL {

    static void test( String url, String name ) throws Exception {
        SmbFile f;

        if( name == null ) name = "";

        System.out.println( "INPUT[" + url + ", " + name + "]");
        try {
            f = new SmbFile( url, name );
        } catch( Exception e ) {
            e.printStackTrace();
            return;
        }

        System.out.print( "toString()         : " );
        try {
            System.out.println( f.toString() );
        } catch( Exception e ) {
            e.printStackTrace(); System.out.println();
        }
        System.out.print( "getCanonicalPath() : " );
        try {
            System.out.println( f.getCanonicalPath() );
        } catch( Exception e ) {
            e.printStackTrace(); System.out.println();
        }
        System.out.print( "getUncPath()       : " );
        try {
            System.out.println( f.getUncPath() );
        } catch( Exception e ) {
            e.printStackTrace(); System.out.println();
        }
        System.out.print( "getName()          : " );
        try {
            System.out.println( f.getName() );
        } catch( Exception e ) {
            e.printStackTrace(); System.out.println();
        }
        System.out.print( "getParent()        : " );
        try {
            System.out.println( f.getParent() );
        } catch( Exception e ) {
            e.printStackTrace(); System.out.println();
        }
        System.out.print( "getPath()          : " );
        try {
            System.out.println( f.getPath() );
        } catch( Exception e ) {
            e.printStackTrace(); System.out.println();
        }
        System.out.print( "getServer()        : " );
        try {
            System.out.println( f.getServer() );
        } catch( Exception e ) {
            e.printStackTrace(); System.out.println();
        }
        System.out.print( "getShare()         : " );
        try {
            System.out.println( f.getShare() );
        } catch( Exception e ) {
            e.printStackTrace(); System.out.println();
        }
        System.out.print( "exists()           : " );
        try {
            System.out.println( f.exists() );
        } catch( Exception e ) {
            e.printStackTrace(); System.out.println();
        }
        System.out.print( "isDirectory()      : " );
        try {
            System.out.println( f.isDirectory() );
        } catch( Exception e ) {
            e.printStackTrace(); System.out.println();
        }
        System.out.print( "isFile()           : " );
        try {
            System.out.println( f.isFile() );
        } catch( Exception e ) {
            e.printStackTrace(); System.out.println();
        }
        System.out.print( "length()           : " );
        try {
            System.out.println( f.length() );
        } catch( Exception e ) {
            e.printStackTrace(); System.out.println();
        }
        System.out.print( "lastModified()     : " );
        try {
            System.out.println( (new Date( f.lastModified() )));
        } catch( Exception e ) {
            e.printStackTrace(); System.out.println();
        }
        System.out.print( "toURL().toString() : " );
        try {
            System.out.println( f.toURL() );
        } catch( Exception e ) {
            e.printStackTrace(); System.out.println();
        }

        System.in.read();
    }

    public static void main( String argv[] ) throws Exception {
        String workgroup, server, share, path, file;

        if( argv.length < 5 ) {
            System.err.println( "TestSmbURL workgroup server share path file" );
            System.exit( 1 );
        }

        workgroup = argv[0];
        server = argv[1];
        share = argv[2];
        path = argv[3];
        file = argv[4];

/*
        System.out.println();
        System.out.println( "-- UNUSUAL --" );
        System.out.println();
        test( "smb://" + server, "../" + server + "/" + share );
        test( "smb://foo", "../" + workgroup );
        test( "smb://", ".." );
*/

        System.out.println();
        System.out.println( "-- BASICS: ONE ARGUMENT --" );
        System.out.println();
        test( "smb://" + server + "/" + share + "/" + path + "/" + file, null );
        test( "smb://" + server + "/" + share + "/" + path + "/", null );
        test( "smb://" + server + "/" + share + "/", null );
        test( "smb://" + server + "/", null );
        test( "smb://" + workgroup + "/", null );
        test( "smb://", null );

        System.out.println();
        System.out.println( "-- BASICS: TWO ARGUMENTS --" );
        System.out.println();
        test( "smb://" + server + "/" + share + "/" + path + "/", file);
        test( "smb://" + server + "/" + share + "/", path + "/" + file);
        test( "smb://" + server + "/", share + "/" + path + "/" + file);
        test( "smb://", server + "/" + share + "/" + path + "/" + file);
        test( "smb://", "smb://" + server + "/" + share + "/" + path + "/" + file);
        test( "smb://", "smb://" + server + "/");
        test( "smb://", "smb://" + workgroup + "/");
        test( "smb://", "smb://");
        test( "smb://" + server + "/share/", "smb://");

        System.out.println();
        System.out.println( "-- CANONICALIZATION --" );
        System.out.println();
        test( "smb://" + server + "/" + share + "/foo/../" + path + "/" + file, null );
        test( "smb://" + server + "/foo/bar/.././../" + share + "/" + path + "/" + file, null );
        test( "smb://" + server + "/foo/bar/.././.././" + share + "/fake/../" + path + "/" + file, null );
        test( "smb://" + server + "/foo/bar/.././.././", share + "/fake/../" + path + "/" + file);
        test( "smb://", server + "/foo/bar/.././.././" + share + "/fake/../" + path + "/" + file);
    }
}

