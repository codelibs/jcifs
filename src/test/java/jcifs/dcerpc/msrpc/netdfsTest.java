package jcifs.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;
import jcifs.dcerpc.ndr.NdrLong;

public class netdfsTest {

    private NdrBuffer mockNdrBuffer;

    @BeforeEach
    void setUp() {
        mockNdrBuffer = mock(NdrBuffer.class);
    }

    @Test
    void testGetSyntax() {
        assertEquals("4fc742e0-4a10-11cf-8273-00aa004ae673:3.0", netdfs.getSyntax());
    }

    @Test
    void testDfsInfo1_EncodeDecode() throws NdrException {
        netdfs.DfsInfo1 info1 = new netdfs.DfsInfo1();
        info1.entry_path = "test_path";

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        info1.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsInfo1 decodedInfo1 = new netdfs.DfsInfo1();
        decodedInfo1.decode(src);

        assertEquals(info1.entry_path, decodedInfo1.entry_path);
    }

    @Test
    void testDfsInfo1_EncodeDecode_NullEntryPath() throws NdrException {
        netdfs.DfsInfo1 info1 = new netdfs.DfsInfo1();
        info1.entry_path = null;

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        info1.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsInfo1 decodedInfo1 = new netdfs.DfsInfo1();
        decodedInfo1.decode(src);

        assertNull(decodedInfo1.entry_path);
    }

    @Test
    void testDfsEnumArray1_EncodeDecode() throws NdrException {
        netdfs.DfsEnumArray1 enumArray1 = new netdfs.DfsEnumArray1();
        enumArray1.count = 2;
        enumArray1.s = new netdfs.DfsInfo1[2];
        enumArray1.s[0] = new netdfs.DfsInfo1();
        enumArray1.s[0].entry_path = "path1";
        enumArray1.s[1] = new netdfs.DfsInfo1();
        enumArray1.s[1].entry_path = "path2";

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        enumArray1.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsEnumArray1 decodedEnumArray1 = new netdfs.DfsEnumArray1();
        decodedEnumArray1.decode(src);

        assertEquals(enumArray1.count, decodedEnumArray1.count);
        assertEquals(enumArray1.s[0].entry_path, decodedEnumArray1.s[0].entry_path);
        assertEquals(enumArray1.s[1].entry_path, decodedEnumArray1.s[1].entry_path);
    }

    @Test
    void testDfsEnumArray1_EncodeDecode_EmptyArray() throws NdrException {
        netdfs.DfsEnumArray1 enumArray1 = new netdfs.DfsEnumArray1();
        enumArray1.count = 0;
        enumArray1.s = new netdfs.DfsInfo1[0];

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        enumArray1.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsEnumArray1 decodedEnumArray1 = new netdfs.DfsEnumArray1();
        decodedEnumArray1.decode(src);

        assertEquals(0, decodedEnumArray1.count);
        assertNotNull(decodedEnumArray1.s);
        assertEquals(0, decodedEnumArray1.s.length);
    }

    @Test
    void testDfsEnumArray1_EncodeDecode_NullArray() throws NdrException {
        netdfs.DfsEnumArray1 enumArray1 = new netdfs.DfsEnumArray1();
        enumArray1.count = 0;
        enumArray1.s = null;

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        enumArray1.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsEnumArray1 decodedEnumArray1 = new netdfs.DfsEnumArray1();
        decodedEnumArray1.decode(src);

        assertEquals(0, decodedEnumArray1.count);
        assertNull(decodedEnumArray1.s);
    }

    @Test
    void testDfsStorageInfo_EncodeDecode() throws NdrException {
        netdfs.DfsStorageInfo storageInfo = new netdfs.DfsStorageInfo();
        storageInfo.state = netdfs.DFS_STORAGE_STATE_ONLINE;
        storageInfo.server_name = "server1";
        storageInfo.share_name = "share1";

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        storageInfo.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsStorageInfo decodedStorageInfo = new netdfs.DfsStorageInfo();
        decodedStorageInfo.decode(src);

        assertEquals(storageInfo.state, decodedStorageInfo.state);
        assertEquals(storageInfo.server_name, decodedStorageInfo.server_name);
        assertEquals(storageInfo.share_name, decodedStorageInfo.share_name);
    }

    @Test
    void testDfsStorageInfo_EncodeDecode_NullStrings() throws NdrException {
        netdfs.DfsStorageInfo storageInfo = new netdfs.DfsStorageInfo();
        storageInfo.state = netdfs.DFS_STORAGE_STATE_OFFLINE;
        storageInfo.server_name = null;
        storageInfo.share_name = null;

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        storageInfo.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsStorageInfo decodedStorageInfo = new netdfs.DfsStorageInfo();
        decodedStorageInfo.decode(src);

        assertEquals(storageInfo.state, decodedStorageInfo.state);
        assertNull(decodedStorageInfo.server_name);
        assertNull(decodedStorageInfo.share_name);
    }

    @Test
    void testDfsInfo3_EncodeDecode() throws NdrException {
        netdfs.DfsInfo3 info3 = new netdfs.DfsInfo3();
        info3.path = "dfs_path";
        info3.comment = "dfs_comment";
        info3.state = netdfs.DFS_VOLUME_FLAVOR_AD_BLOB;
        info3.num_stores = 1;
        info3.stores = new netdfs.DfsStorageInfo[1];
        info3.stores[0] = new netdfs.DfsStorageInfo();
        info3.stores[0].state = netdfs.DFS_STORAGE_STATE_ACTIVE;
        info3.stores[0].server_name = "store_server";
        info3.stores[0].share_name = "store_share";

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        info3.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsInfo3 decodedInfo3 = new netdfs.DfsInfo3();
        decodedInfo3.decode(src);

        assertEquals(info3.path, decodedInfo3.path);
        assertEquals(info3.comment, decodedInfo3.comment);
        assertEquals(info3.state, decodedInfo3.state);
        assertEquals(info3.num_stores, decodedInfo3.num_stores);
        assertEquals(info3.stores[0].state, decodedInfo3.stores[0].state);
        assertEquals(info3.stores[0].server_name, decodedInfo3.stores[0].server_name);
        assertEquals(info3.stores[0].share_name, decodedInfo3.stores[0].share_name);
    }

    @Test
    void testDfsInfo3_EncodeDecode_NullStringsAndEmptyStores() throws NdrException {
        netdfs.DfsInfo3 info3 = new netdfs.DfsInfo3();
        info3.path = null;
        info3.comment = null;
        info3.state = netdfs.DFS_VOLUME_FLAVOR_STANDALONE;
        info3.num_stores = 0;
        info3.stores = new netdfs.DfsStorageInfo[0];

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        info3.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsInfo3 decodedInfo3 = new netdfs.DfsInfo3();
        decodedInfo3.decode(src);

        assertNull(decodedInfo3.path);
        assertNull(decodedInfo3.comment);
        assertEquals(info3.state, decodedInfo3.state);
        assertEquals(0, decodedInfo3.num_stores);
        assertNotNull(decodedInfo3.stores);
        assertEquals(0, decodedInfo3.stores.length);
    }

    @Test
    void testDfsInfo3_EncodeDecode_NullStoresArray() throws NdrException {
        netdfs.DfsInfo3 info3 = new netdfs.DfsInfo3();
        info3.path = "dfs_path";
        info3.comment = "dfs_comment";
        info3.state = netdfs.DFS_VOLUME_FLAVOR_AD_BLOB;
        info3.num_stores = 0;
        info3.stores = null;

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        info3.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsInfo3 decodedInfo3 = new netdfs.DfsInfo3();
        decodedInfo3.decode(src);

        assertEquals(info3.path, decodedInfo3.path);
        assertEquals(info3.comment, decodedInfo3.comment);
        assertEquals(info3.state, decodedInfo3.state);
        assertEquals(0, decodedInfo3.num_stores);
        assertNull(decodedInfo3.stores);
    }

    @Test
    void testDfsEnumArray3_EncodeDecode() throws NdrException {
        netdfs.DfsEnumArray3 enumArray3 = new netdfs.DfsEnumArray3();
        enumArray3.count = 1;
        enumArray3.s = new netdfs.DfsInfo3[1];
        enumArray3.s[0] = new netdfs.DfsInfo3();
        enumArray3.s[0].path = "path_enum3";
        enumArray3.s[0].comment = "comment_enum3";
        enumArray3.s[0].state = netdfs.DFS_VOLUME_FLAVOR_STANDALONE;
        enumArray3.s[0].num_stores = 0;
        enumArray3.s[0].stores = new netdfs.DfsStorageInfo[0];

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        enumArray3.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsEnumArray3 decodedEnumArray3 = new netdfs.DfsEnumArray3();
        decodedEnumArray3.decode(src);

        assertEquals(enumArray3.count, decodedEnumArray3.count);
        assertEquals(enumArray3.s[0].path, decodedEnumArray3.s[0].path);
        assertEquals(enumArray3.s[0].comment, decodedEnumArray3.s[0].comment);
        assertEquals(enumArray3.s[0].state, decodedEnumArray3.s[0].state);
        assertEquals(enumArray3.s[0].num_stores, decodedEnumArray3.s[0].num_stores);
        assertNotNull(decodedEnumArray3.s[0].stores);
        assertEquals(0, decodedEnumArray3.s[0].stores.length);
    }

    @Test
    void testDfsEnumArray3_EncodeDecode_EmptyArray() throws NdrException {
        netdfs.DfsEnumArray3 enumArray3 = new netdfs.DfsEnumArray3();
        enumArray3.count = 0;
        enumArray3.s = new netdfs.DfsInfo3[0];

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        enumArray3.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsEnumArray3 decodedEnumArray3 = new netdfs.DfsEnumArray3();
        decodedEnumArray3.decode(src);

        assertEquals(0, decodedEnumArray3.count);
        assertNotNull(decodedEnumArray3.s);
        assertEquals(0, decodedEnumArray3.s.length);
    }

    @Test
    void testDfsEnumArray3_EncodeDecode_NullArray() throws NdrException {
        netdfs.DfsEnumArray3 enumArray3 = new netdfs.DfsEnumArray3();
        enumArray3.count = 0;
        enumArray3.s = null;

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        enumArray3.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsEnumArray3 decodedEnumArray3 = new netdfs.DfsEnumArray3();
        decodedEnumArray3.decode(src);

        assertEquals(0, decodedEnumArray3.count);
        assertNull(decodedEnumArray3.s);
    }

    @Test
    void testDfsInfo200_EncodeDecode() throws NdrException {
        netdfs.DfsInfo200 info200 = new netdfs.DfsInfo200();
        info200.dfs_name = "dfs_name_200";

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        info200.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsInfo200 decodedInfo200 = new netdfs.DfsInfo200();
        decodedInfo200.decode(src);

        assertEquals(info200.dfs_name, decodedInfo200.dfs_name);
    }

    @Test
    void testDfsInfo200_EncodeDecode_NullDfsName() throws NdrException {
        netdfs.DfsInfo200 info200 = new netdfs.DfsInfo200();
        info200.dfs_name = null;

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        info200.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsInfo200 decodedInfo200 = new netdfs.DfsInfo200();
        decodedInfo200.decode(src);

        assertNull(decodedInfo200.dfs_name);
    }

    @Test
    void testDfsEnumArray200_EncodeDecode() throws NdrException {
        netdfs.DfsEnumArray200 enumArray200 = new netdfs.DfsEnumArray200();
        enumArray200.count = 1;
        enumArray200.s = new netdfs.DfsInfo200[1];
        enumArray200.s[0] = new netdfs.DfsInfo200();
        enumArray200.s[0].dfs_name = "dfs_name_enum200";

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        enumArray200.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsEnumArray200 decodedEnumArray200 = new netdfs.DfsEnumArray200();
        decodedEnumArray200.decode(src);

        assertEquals(enumArray200.count, decodedEnumArray200.count);
        assertEquals(enumArray200.s[0].dfs_name, decodedEnumArray200.s[0].dfs_name);
    }

    @Test
    void testDfsEnumArray200_EncodeDecode_EmptyArray() throws NdrException {
        netdfs.DfsEnumArray200 enumArray200 = new netdfs.DfsEnumArray200();
        enumArray200.count = 0;
        enumArray200.s = new netdfs.DfsInfo200[0];

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        enumArray200.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsEnumArray200 decodedEnumArray200 = new netdfs.DfsEnumArray200();
        decodedEnumArray200.decode(src);

        assertEquals(0, decodedEnumArray200.count);
        assertNotNull(decodedEnumArray200.s);
        assertEquals(0, decodedEnumArray200.s.length);
    }

    @Test
    void testDfsEnumArray200_EncodeDecode_NullArray() throws NdrException {
        netdfs.DfsEnumArray200 enumArray200 = new netdfs.DfsEnumArray200();
        enumArray200.count = 0;
        enumArray200.s = null;

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        enumArray200.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsEnumArray200 decodedEnumArray200 = new netdfs.DfsEnumArray200();
        decodedEnumArray200.decode(src);

        assertEquals(0, decodedEnumArray200.count);
        assertNull(decodedEnumArray200.s);
    }

    @Test
    void testDfsInfo300_EncodeDecode() throws NdrException {
        netdfs.DfsInfo300 info300 = new netdfs.DfsInfo300();
        info300.flags = 123;
        info300.dfs_name = "dfs_name_300";

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        info300.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsInfo300 decodedInfo300 = new netdfs.DfsInfo300();
        decodedInfo300.decode(src);

        assertEquals(info300.flags, decodedInfo300.flags);
        assertEquals(info300.dfs_name, decodedInfo300.dfs_name);
    }

    @Test
    void testDfsInfo300_EncodeDecode_NullDfsName() throws NdrException {
        netdfs.DfsInfo300 info300 = new netdfs.DfsInfo300();
        info300.flags = 456;
        info300.dfs_name = null;

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        info300.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsInfo300 decodedInfo300 = new netdfs.DfsInfo300();
        decodedInfo300.decode(src);

        assertEquals(info300.flags, decodedInfo300.flags);
        assertNull(decodedInfo300.dfs_name);
    }

    @Test
    void testDfsEnumArray300_EncodeDecode() throws NdrException {
        netdfs.DfsEnumArray300 enumArray300 = new netdfs.DfsEnumArray300();
        enumArray300.count = 1;
        enumArray300.s = new netdfs.DfsInfo300[1];
        enumArray300.s[0] = new netdfs.DfsInfo300();
        enumArray300.s[0].flags = 789;
        enumArray300.s[0].dfs_name = "dfs_name_enum300";

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        enumArray300.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsEnumArray300 decodedEnumArray300 = new netdfs.DfsEnumArray300();
        decodedEnumArray300.decode(src);

        assertEquals(enumArray300.count, decodedEnumArray300.count);
        assertEquals(enumArray300.s[0].flags, decodedEnumArray300.s[0].flags);
        assertEquals(enumArray300.s[0].dfs_name, decodedEnumArray300.s[0].dfs_name);
    }

    @Test
    void testDfsEnumArray300_EncodeDecode_EmptyArray() throws NdrException {
        netdfs.DfsEnumArray300 enumArray300 = new netdfs.DfsEnumArray300();
        enumArray300.count = 0;
        enumArray300.s = new netdfs.DfsInfo300[0];

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        enumArray300.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsEnumArray300 decodedEnumArray300 = new netdfs.DfsEnumArray300();
        decodedEnumArray300.decode(src);

        assertEquals(0, decodedEnumArray300.count);
        assertNotNull(decodedEnumArray300.s);
        assertEquals(0, decodedEnumArray300.s.length);
    }

    @Test
    void testDfsEnumArray300_EncodeDecode_NullArray() throws NdrException {
        netdfs.DfsEnumArray300 enumArray300 = new netdfs.DfsEnumArray300();
        enumArray300.count = 0;
        enumArray300.s = null;

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        enumArray300.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsEnumArray300 decodedEnumArray300 = new netdfs.DfsEnumArray300();
        decodedEnumArray300.decode(src);

        assertEquals(0, decodedEnumArray300.count);
        assertNull(decodedEnumArray300.s);
    }

    @Test
    void testDfsEnumStruct_EncodeDecode_Level1() throws NdrException {
        netdfs.DfsEnumStruct enumStruct = new netdfs.DfsEnumStruct();
        enumStruct.level = 1;
        enumStruct.e = new netdfs.DfsEnumArray1();
        ((netdfs.DfsEnumArray1) enumStruct.e).count = 1;
        ((netdfs.DfsEnumArray1) enumStruct.e).s = new netdfs.DfsInfo1[1];
        ((netdfs.DfsEnumArray1) enumStruct.e).s[0] = new netdfs.DfsInfo1();
        ((netdfs.DfsEnumArray1) enumStruct.e).s[0].entry_path = "struct_path_1";

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        enumStruct.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsEnumStruct decodedEnumStruct = new netdfs.DfsEnumStruct();
        decodedEnumStruct.decode(src);

        assertEquals(enumStruct.level, decodedEnumStruct.level);
        assertTrue(decodedEnumStruct.e instanceof netdfs.DfsEnumArray1);
        netdfs.DfsEnumArray1 decodedArray1 = (netdfs.DfsEnumArray1) decodedEnumStruct.e;
        assertEquals(1, decodedArray1.count);
        assertEquals("struct_path_1", decodedArray1.s[0].entry_path);
    }

    @Test
    void testDfsEnumStruct_EncodeDecode_NullE() throws NdrException {
        netdfs.DfsEnumStruct enumStruct = new netdfs.DfsEnumStruct();
        enumStruct.level = 1;
        enumStruct.e = null;

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        enumStruct.encode(dst);

        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        // Use the encoded buffer for decoding
        NdrBuffer src = new NdrBuffer(encodeBuffer, 0);
        netdfs.DfsEnumStruct decodedEnumStruct = new netdfs.DfsEnumStruct();
        decodedEnumStruct.decode(src);

        assertEquals(enumStruct.level, decodedEnumStruct.level);
        assertNull(decodedEnumStruct.e);
    }

    @Test
    void testNetrDfsEnumEx_ConstructorAndGetOpnum() {
        String dfsName = "dfs_name";
        int level = 1;
        int prefmaxlen = 1024;
        netdfs.DfsEnumStruct info = new netdfs.DfsEnumStruct();
        NdrLong totalentries = new NdrLong(0);

        netdfs.NetrDfsEnumEx enumEx = new netdfs.NetrDfsEnumEx(dfsName, level, prefmaxlen, info, totalentries);

        assertEquals(dfsName, enumEx.dfs_name);
        assertEquals(level, enumEx.level);
        assertEquals(prefmaxlen, enumEx.prefmaxlen);
        assertEquals(info, enumEx.info);
        assertEquals(totalentries, enumEx.totalentries);
        assertEquals(0x15, enumEx.getOpnum());
    }

    @Test
    void testNetrDfsEnumEx_EncodeInDecodeOut() throws NdrException {
        String dfsName = "test_dfs";
        int level = 1;
        int prefmaxlen = 100;
        netdfs.DfsEnumStruct info = new netdfs.DfsEnumStruct();
        info.level = 1;
        info.e = new netdfs.DfsEnumArray1();
        ((netdfs.DfsEnumArray1) info.e).count = 1;
        ((netdfs.DfsEnumArray1) info.e).s = new netdfs.DfsInfo1[1];
        ((netdfs.DfsEnumArray1) info.e).s[0] = new netdfs.DfsInfo1();
        ((netdfs.DfsEnumArray1) info.e).s[0].entry_path = "encoded_path";

        NdrLong totalentries = new NdrLong(5);

        netdfs.NetrDfsEnumEx enumEx = new netdfs.NetrDfsEnumEx(dfsName, level, prefmaxlen, info, totalentries);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        enumEx.encode_in(dst);

        // Simulate decode_out
        // The decode_out method expects the info and totalentries to be already initialized
        // and will decode into them.
        netdfs.DfsEnumStruct decodedInfo = new netdfs.DfsEnumStruct();
        NdrLong decodedTotalEntries = new NdrLong(0);
        netdfs.NetrDfsEnumEx decodedEnumEx = new netdfs.NetrDfsEnumEx(null, 0, 0, decodedInfo, decodedTotalEntries);

        // Manually encode the expected output for decode_out
        byte[] encodeBufferOut = new byte[1024];
        NdrBuffer dstOut = new NdrBuffer(encodeBufferOut, 0);

        // Simulate info pointer (non-null)
        dstOut.enc_ndr_long(1); // Non-null pointer for info
        info.encode(dstOut); // Encode the info structure

        // Simulate totalentries pointer (non-null)
        dstOut.enc_ndr_long(1); // Non-null pointer for totalentries
        totalentries.encode(dstOut); // Encode the totalentries

        dstOut.enc_ndr_long(0); // Simulate retval

        // Use the encoded data for decoding
        NdrBuffer srcOut = new NdrBuffer(encodeBufferOut, 0);
        decodedEnumEx.decode_out(srcOut);

        assertEquals(0, decodedEnumEx.retval);
        assertEquals(info.level, decodedEnumEx.info.level);
        assertTrue(decodedEnumEx.info.e instanceof netdfs.DfsEnumArray1);
        assertEquals(((netdfs.DfsEnumArray1) info.e).count, ((netdfs.DfsEnumArray1) decodedEnumEx.info.e).count);
        assertEquals(((netdfs.DfsEnumArray1) info.e).s[0].entry_path, ((netdfs.DfsEnumArray1) decodedEnumEx.info.e).s[0].entry_path);
        assertEquals(totalentries.value, decodedEnumEx.totalentries.value);
    }

    @Test
    void testNetrDfsEnumEx_EncodeInDecodeOut_NullInfoAndTotalEntries() throws NdrException {
        String dfsName = "test_dfs_nulls";
        int level = 1;
        int prefmaxlen = 100;
        netdfs.DfsEnumStruct info = null;
        NdrLong totalentries = null;

        netdfs.NetrDfsEnumEx enumEx = new netdfs.NetrDfsEnumEx(dfsName, level, prefmaxlen, info, totalentries);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Create buffer for encoding - initially allocate some space
        byte[] encodeBuffer = new byte[1024];
        NdrBuffer dst = new NdrBuffer(encodeBuffer, 0);
        enumEx.encode_in(dst);

        // Simulate decode_out with null info and totalentries
        netdfs.NetrDfsEnumEx decodedEnumEx = new netdfs.NetrDfsEnumEx(null, 0, 0, null, null);

        // Manually encode the expected output for decode_out
        byte[] encodeBufferOut2 = new byte[1024];
        NdrBuffer dstOut = new NdrBuffer(encodeBufferOut2, 0);

        // Simulate info pointer (null)
        dstOut.enc_ndr_long(0); // Null pointer for info

        // Simulate totalentries pointer (null)
        dstOut.enc_ndr_long(0); // Null pointer for totalentries

        dstOut.enc_ndr_long(0); // Simulate retval

        // Use the encoded data for decoding
        NdrBuffer srcOut = new NdrBuffer(encodeBufferOut2, 0);
        decodedEnumEx.decode_out(srcOut);

        assertEquals(0, decodedEnumEx.retval);
        assertNull(decodedEnumEx.info);
        assertNull(decodedEnumEx.totalentries);
    }
}
