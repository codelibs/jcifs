package jcifs.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.dcerpc.DcerpcConstants;
import jcifs.dcerpc.rpc.sid_t;

@ExtendWith(MockitoExtension.class)
class MsrpcLookupSidsTest {

    @Mock
    private LsaPolicyHandle mockPolicyHandle;

    @Mock
    private sid_t mockSidT;

    private MsrpcLookupSids lookupSids;
    private jcifs.SID[] testSids;

    @BeforeEach
    void setUp() {
        // Setup is minimal - mocks are configured per test as needed
    }

    @Test
    void constructor_shouldInitializeWithValidParameters() {
        // Arrange
        jcifs.SID mockSid1 = mock(jcifs.SID.class);
        jcifs.SID mockSid2 = mock(jcifs.SID.class);
        when(mockSid1.unwrap(sid_t.class)).thenReturn(mockSidT);
        when(mockSid2.unwrap(sid_t.class)).thenReturn(mockSidT);
        testSids = new jcifs.SID[] { mockSid1, mockSid2 };

        // Act
        lookupSids = new MsrpcLookupSids(mockPolicyHandle, testSids);

        // Assert
        assertNotNull(lookupSids);
        assertEquals(0, lookupSids.getPtype());
        assertEquals(DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG, lookupSids.getFlags());
    }

    @Test
    void constructor_shouldHandleSingleSid() {
        // Arrange
        jcifs.SID mockSid = mock(jcifs.SID.class);
        when(mockSid.unwrap(sid_t.class)).thenReturn(mockSidT);
        testSids = new jcifs.SID[] { mockSid };

        // Act
        lookupSids = new MsrpcLookupSids(mockPolicyHandle, testSids);

        // Assert
        assertNotNull(lookupSids);
        assertEquals(0, lookupSids.getPtype());
        assertEquals(DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG, lookupSids.getFlags());
    }

    @Test
    void constructor_shouldHandleMultipleSids() {
        // Arrange
        jcifs.SID mockSid1 = mock(jcifs.SID.class);
        jcifs.SID mockSid2 = mock(jcifs.SID.class);
        jcifs.SID mockSid3 = mock(jcifs.SID.class);
        when(mockSid1.unwrap(sid_t.class)).thenReturn(mockSidT);
        when(mockSid2.unwrap(sid_t.class)).thenReturn(mockSidT);
        when(mockSid3.unwrap(sid_t.class)).thenReturn(mockSidT);
        testSids = new jcifs.SID[] { mockSid1, mockSid2, mockSid3 };

        // Act
        lookupSids = new MsrpcLookupSids(mockPolicyHandle, testSids);

        // Assert
        assertNotNull(lookupSids);
        assertEquals(0, lookupSids.getPtype());
        assertEquals(DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG, lookupSids.getFlags());
    }

    @Test
    void constructor_shouldHandleEmptySidArray() {
        // Arrange
        testSids = new jcifs.SID[0];

        // Act
        lookupSids = new MsrpcLookupSids(mockPolicyHandle, testSids);

        // Assert
        assertNotNull(lookupSids);
        assertEquals(0, lookupSids.getPtype());
        assertEquals(DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG, lookupSids.getFlags());
    }

    @Test
    void constructor_shouldAcceptNullPolicyHandle() {
        // Arrange
        jcifs.SID mockSid = mock(jcifs.SID.class);
        when(mockSid.unwrap(sid_t.class)).thenReturn(mockSidT);
        testSids = new jcifs.SID[] { mockSid };

        // Act & Assert - Constructor accepts null, no exception thrown
        assertDoesNotThrow(() -> {
            new MsrpcLookupSids(null, testSids);
        });
    }

    @Test
    void constructor_shouldThrowExceptionWithNullSids() {
        // Act & Assert - Null SID array causes NPE when accessing length
        assertThrows(NullPointerException.class, () -> {
            new MsrpcLookupSids(mockPolicyHandle, null);
        });
    }

    @Test
    void constructor_shouldSetCorrectSuperclassParameters() throws Exception {
        // Arrange
        jcifs.SID mockSid1 = mock(jcifs.SID.class);
        jcifs.SID mockSid2 = mock(jcifs.SID.class);
        when(mockSid1.unwrap(sid_t.class)).thenReturn(mockSidT);
        when(mockSid2.unwrap(sid_t.class)).thenReturn(mockSidT);
        testSids = new jcifs.SID[] { mockSid1, mockSid2 };

        // Act
        lookupSids = new MsrpcLookupSids(mockPolicyHandle, testSids);

        // Assert using reflection to verify superclass fields
        Field handleField = lsarpc.LsarLookupSids.class.getDeclaredField("handle");
        handleField.setAccessible(true);
        assertSame(mockPolicyHandle, handleField.get(lookupSids));

        Field countField = lsarpc.LsarLookupSids.class.getDeclaredField("count");
        countField.setAccessible(true);
        assertEquals(2, countField.get(lookupSids));

        Field levelField = lsarpc.LsarLookupSids.class.getDeclaredField("level");
        levelField.setAccessible(true);
        assertEquals((short) 1, levelField.get(lookupSids));
    }

    @Test
    void constructor_shouldCreateCorrectLsarSidArrayX() throws Exception {
        // Arrange
        jcifs.SID mockSid1 = mock(jcifs.SID.class);
        jcifs.SID mockSid2 = mock(jcifs.SID.class);
        when(mockSid1.unwrap(sid_t.class)).thenReturn(mockSidT);
        when(mockSid2.unwrap(sid_t.class)).thenReturn(mockSidT);
        testSids = new jcifs.SID[] { mockSid1, mockSid2 };

        // Act
        lookupSids = new MsrpcLookupSids(mockPolicyHandle, testSids);

        // Assert using reflection
        Field sidsField = lsarpc.LsarLookupSids.class.getDeclaredField("sids");
        sidsField.setAccessible(true);
        Object sidsObj = sidsField.get(lookupSids);

        assertNotNull(sidsObj);
        assertTrue(sidsObj instanceof LsarSidArrayX);
    }

    @Test
    void constructor_shouldCreateLsarRefDomainList() throws Exception {
        // Arrange
        jcifs.SID mockSid = mock(jcifs.SID.class);
        when(mockSid.unwrap(sid_t.class)).thenReturn(mockSidT);
        testSids = new jcifs.SID[] { mockSid };

        // Act
        lookupSids = new MsrpcLookupSids(mockPolicyHandle, testSids);

        // Assert using reflection
        Field domainsField = lsarpc.LsarLookupSids.class.getDeclaredField("domains");
        domainsField.setAccessible(true);
        Object domainsObj = domainsField.get(lookupSids);

        assertNotNull(domainsObj);
        assertTrue(domainsObj instanceof lsarpc.LsarRefDomainList);
    }

    @Test
    void constructor_shouldCreateLsarTransNameArray() throws Exception {
        // Arrange
        jcifs.SID mockSid = mock(jcifs.SID.class);
        when(mockSid.unwrap(sid_t.class)).thenReturn(mockSidT);
        testSids = new jcifs.SID[] { mockSid };

        // Act
        lookupSids = new MsrpcLookupSids(mockPolicyHandle, testSids);

        // Assert using reflection
        Field namesField = lsarpc.LsarLookupSids.class.getDeclaredField("names");
        namesField.setAccessible(true);
        Object namesObj = namesField.get(lookupSids);

        assertNotNull(namesObj);
        assertTrue(namesObj instanceof lsarpc.LsarTransNameArray);
    }

    @ParameterizedTest
    @ValueSource(ints = { 1, 5, 10, 20, 50 })
    void constructor_shouldHandleVariousSidArraySizes(int size) {
        // Arrange
        testSids = new jcifs.SID[size];
        for (int i = 0; i < size; i++) {
            testSids[i] = mock(jcifs.SID.class);
            when(testSids[i].unwrap(sid_t.class)).thenReturn(mockSidT);
        }

        // Act
        lookupSids = new MsrpcLookupSids(mockPolicyHandle, testSids);

        // Assert
        assertNotNull(lookupSids);
        assertEquals(0, lookupSids.getPtype());
        assertEquals(DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG, lookupSids.getFlags());
    }

    @Test
    void constructor_shouldHandleSidsWithNullElements() {
        // Arrange
        jcifs.SID mockSid1 = mock(jcifs.SID.class);
        jcifs.SID mockSid2 = mock(jcifs.SID.class);
        when(mockSid1.unwrap(sid_t.class)).thenReturn(mockSidT);
        // Don't stub mockSid2 since it won't be reached due to NPE on null element
        testSids = new jcifs.SID[] { mockSid1, null, mockSid2 };

        // Act & Assert - This should throw an exception when LsarSidArrayX tries to process null
        assertThrows(NullPointerException.class, () -> {
            new MsrpcLookupSids(mockPolicyHandle, testSids);
        });
    }

    @Test
    void getOpnum_shouldReturnCorrectValue() {
        // Arrange
        jcifs.SID mockSid = mock(jcifs.SID.class);
        when(mockSid.unwrap(sid_t.class)).thenReturn(mockSidT);
        testSids = new jcifs.SID[] { mockSid };
        lookupSids = new MsrpcLookupSids(mockPolicyHandle, testSids);

        // Act
        int opnum = lookupSids.getOpnum();

        // Assert
        assertEquals(0x0f, opnum);
    }

    @Test
    void constructor_shouldPreservePolicyHandleReference() throws Exception {
        // Arrange
        jcifs.SID mockSid = mock(jcifs.SID.class);
        when(mockSid.unwrap(sid_t.class)).thenReturn(mockSidT);
        testSids = new jcifs.SID[] { mockSid };
        LsaPolicyHandle specificHandle = mock(LsaPolicyHandle.class);

        // Act
        lookupSids = new MsrpcLookupSids(specificHandle, testSids);

        // Assert using reflection
        Field handleField = lsarpc.LsarLookupSids.class.getDeclaredField("handle");
        handleField.setAccessible(true);
        assertSame(specificHandle, handleField.get(lookupSids));
    }

    @Test
    void constructor_shouldHandleLargeSidArray() {
        // Arrange
        int largeSize = 1000;
        testSids = new jcifs.SID[largeSize];
        for (int i = 0; i < largeSize; i++) {
            testSids[i] = mock(jcifs.SID.class);
            when(testSids[i].unwrap(sid_t.class)).thenReturn(mockSidT);
        }

        // Act
        lookupSids = new MsrpcLookupSids(mockPolicyHandle, testSids);

        // Assert
        assertNotNull(lookupSids);
        assertEquals(0, lookupSids.getPtype());
        assertEquals(DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG, lookupSids.getFlags());
    }

    @Test
    void inheritance_shouldExtendLsarLookupSids() {
        // Arrange
        jcifs.SID mockSid = mock(jcifs.SID.class);
        when(mockSid.unwrap(sid_t.class)).thenReturn(mockSidT);
        testSids = new jcifs.SID[] { mockSid };

        // Act
        lookupSids = new MsrpcLookupSids(mockPolicyHandle, testSids);

        // Assert
        assertTrue(lookupSids instanceof lsarpc.LsarLookupSids);
    }

    @Test
    void constructor_shouldSetPacketTypeToZero() {
        // Arrange
        jcifs.SID mockSid1 = mock(jcifs.SID.class);
        jcifs.SID mockSid2 = mock(jcifs.SID.class);
        when(mockSid1.unwrap(sid_t.class)).thenReturn(mockSidT);
        when(mockSid2.unwrap(sid_t.class)).thenReturn(mockSidT);
        testSids = new jcifs.SID[] { mockSid1, mockSid2 };

        // Act
        lookupSids = new MsrpcLookupSids(mockPolicyHandle, testSids);

        // Assert
        assertEquals(0, lookupSids.getPtype());
    }

    @Test
    void constructor_shouldSetCorrectFragmentFlags() {
        // Arrange
        jcifs.SID mockSid = mock(jcifs.SID.class);
        when(mockSid.unwrap(sid_t.class)).thenReturn(mockSidT);
        testSids = new jcifs.SID[] { mockSid };

        // Act
        lookupSids = new MsrpcLookupSids(mockPolicyHandle, testSids);

        // Assert
        assertTrue((lookupSids.getFlags() & DcerpcConstants.DCERPC_FIRST_FRAG) != 0);
        assertTrue((lookupSids.getFlags() & DcerpcConstants.DCERPC_LAST_FRAG) != 0);
    }

    @Test
    void constructor_shouldPassCorrectCountToSuperclass() throws Exception {
        // Arrange
        int expectedCount = 7;
        testSids = new jcifs.SID[expectedCount];
        for (int i = 0; i < expectedCount; i++) {
            testSids[i] = mock(jcifs.SID.class);
            when(testSids[i].unwrap(sid_t.class)).thenReturn(mockSidT);
        }

        // Act
        lookupSids = new MsrpcLookupSids(mockPolicyHandle, testSids);

        // Assert using reflection
        Field countField = lsarpc.LsarLookupSids.class.getDeclaredField("count");
        countField.setAccessible(true);
        assertEquals(expectedCount, countField.get(lookupSids));
    }
}