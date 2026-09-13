package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * What a crawler reads back from the entries of a directory listing.
 *
 * <p>
 * {@code listFiles()} builds every child through the package-private constructor that carries the attributes the
 * server put in the listing, so a crawler asking a listed child whether it is a file, how long it is or when it
 * changed is answered from that listing. The crawler then queues {@code getURL().toExternalForm()} and opens a new
 * {@code SmbFile} from that string later. The children here are built exactly the way {@code doFindFirstNext} builds
 * them, which is what lets these tests run without a server.
 * </p>
 */
class SmbFileListingTest {

    private static final long CREATED = 1_600_000_000_000L;
    private static final long MODIFIED = 1_700_000_000_000L;

    private NtlmPasswordAuthentication auth;
    private SmbFile dir;

    @BeforeEach
    void setUp() throws Exception {
        this.auth = new NtlmPasswordAuthentication("DOMAIN", "crawler", "secret");
        this.dir = new SmbFile("smb1://server/share/dir/", this.auth);
    }

    private SmbFile listed(final String name, final int attributes, final long size) throws Exception {
        return new SmbFile(this.dir, name, SmbFile.TYPE_FILESYSTEM, attributes, CREATED, MODIFIED, size);
    }

    @Test
    @DisplayName("a listed file reports its type, size and times from the listing")
    void listedFileReportsTheListedAttributes() throws Exception {
        final SmbFile file = listed("report.pdf", SmbFile.ATTR_ARCHIVE, 12_345L);

        assertTrue(file.isFile());
        assertFalse(file.isDirectory());
        assertEquals(12_345L, file.length());
        assertEquals(MODIFIED, file.lastModified());
        assertEquals(CREATED, file.createTime());
    }

    @Test
    @DisplayName("a listed file names itself, its server and the credentials it was listed with")
    void listedFileKeepsItsIdentity() throws Exception {
        final SmbFile file = listed("report.pdf", SmbFile.ATTR_ARCHIVE, 1L);

        assertEquals("report.pdf", file.getName());
        assertEquals("server", file.getServer());
        assertEquals("smb1://server/share/dir/report.pdf", file.getPath());
        assertSame(this.auth, file.getPrincipal(), "a child must reuse the credentials of the directory it was listed from");
    }

    @Test
    @DisplayName("a listed directory reports that it is a directory and keeps a trailing slash")
    void listedDirectoryIsADirectory() throws Exception {
        final SmbFile sub = listed("sub", SmbFile.ATTR_DIRECTORY, 0L);

        assertTrue(sub.isDirectory());
        assertFalse(sub.isFile());
        assertEquals("sub/", sub.getName());
        assertEquals("smb1://server/share/dir/sub/", sub.getURL().toExternalForm());
    }

    @Test
    @DisplayName("canRead() is exists() over SMB1, so a listed file reports that it can be read")
    void listedFileReportsThatItCanBeRead() throws Exception {
        // SMB1 has no way to ask for the access a server grants, and canRead() is documented to call exists().
        // A listed child exists by construction, so this answers true whatever the file's ACL says.
        assertTrue(listed("secret.txt", SmbFile.ATTR_ARCHIVE, 1L).canRead());
    }

    @ParameterizedTest
    @ValueSource(longs = { 0L, 1L, 65_536L, Integer.MAX_VALUE })
    @DisplayName("getContentLength() is the listed size of a file that fits in an int")
    void contentLengthIsTheListedSize(final long size) throws Exception {
        assertEquals(size, listed("data.bin", SmbFile.ATTR_ARCHIVE, size).getContentLength());
    }

    @Test
    @DisplayName("getHeaderFields() is an empty map rather than null")
    void headerFieldsAreEmpty() throws Exception {
        final Map<String, List<String>> fields = listed("data.bin", SmbFile.ATTR_ARCHIVE, 1L).getHeaderFields();

        assertNotNull(fields);
        assertTrue(fields.isEmpty(), "an SMB file has no header fields, but reported " + fields);
    }

    @ParameterizedTest
    @ValueSource(strings = { "日本語ファイル.txt", "with space.txt", "a+b.txt", "a&b.txt", "100%.txt", "%E3%81%82.txt", "a#b.txt", "a;b.txt",
            "~$draft.docx" })
    @DisplayName("a listed file opened again from its URL addresses the same path on the server")
    void listedFileReopensFromItsUrl(final String name) throws Exception {
        final SmbFile file = listed(name, SmbFile.ATTR_ARCHIVE, 1L);
        final String url = file.getURL().toExternalForm();

        final SmbFile reopened = new SmbFile(url, this.auth);

        assertEquals("\\dir\\" + name, file.getUncPath0(), "the listed child should address the name the server returned");
        assertEquals(file.getUncPath0(), reopened.getUncPath0(), "reopening " + url + " addresses a different path");
        assertEquals(name, reopened.getName());
        assertEquals("share", reopened.getShare());
    }

    @ParameterizedTest
    @ValueSource(strings = { "資料 2024", "a#b", "100%" })
    @DisplayName("a listed directory opened again from its URL addresses the same path and can still be listed")
    void listedDirectoryReopensFromItsUrl(final String name) throws Exception {
        final SmbFile sub = listed(name, SmbFile.ATTR_DIRECTORY, 0L);
        final String url = sub.getURL().toExternalForm();

        final SmbFile reopened = new SmbFile(url, this.auth);

        // Listing a directory requires its URL to end with '/', so losing the slash would stop the crawl there.
        assertTrue(url.endsWith("/"), "a directory URL has to end with '/' to be listed: " + url);
        assertEquals(sub.getUncPath0(), reopened.getUncPath0(), "reopening " + url + " addresses a different path");
        assertEquals(name + "/", reopened.getName());
    }
}
