package jcifs.dcerpc.msrpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import java.lang.reflect.Field;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jcifs.dcerpc.DcerpcConstants;
import jcifs.dcerpc.DcerpcMessage;
import jcifs.dcerpc.msrpc.lsarpc.LsarSidArray;
import jcifs.dcerpc.msrpc.SamrAliasHandle;

/**
 * Tests for the MsrpcGetMembersInAlias class.
 */
class MsrpcGetMembersInAliasTest {

    private SamrAliasHandle aliasHandle;
    private LsarSidArray sids;

    @BeforeEach
    void setUp() {
        // Create mock objects for the constructor parameters
        aliasHandle = mock(SamrAliasHandle.class);
        sids = mock(LsarSidArray.class);
    }

    /**
     * Test method for {@link jcifs.dcerpc.msrpc.MsrpcGetMembersInAlias#MsrpcGetMembersInAlias(SamrAliasHandle, LsarSidArray)}.
     * Verifies that the constructor correctly initializes the object's fields using reflection for protected members.
     */
    @Test
    void testConstructor() throws NoSuchFieldException, IllegalAccessException {
        // Create an instance of the class to be tested
        MsrpcGetMembersInAlias request = new MsrpcGetMembersInAlias(aliasHandle, sids);

        // Assert that the public 'sids' field is initialized as expected
        assertEquals(sids, request.sids, "The 'sids' field should be initialized by the constructor.");

        // Use reflection to access and verify protected fields from the parent class DcerpcMessage
        Field ptypeField = DcerpcMessage.class.getDeclaredField("ptype");
        ptypeField.setAccessible(true);
        int ptypeValue = (int) ptypeField.get(request);
        assertEquals(0, ptypeValue, "The 'ptype' field should be initialized to 0.");

        Field flagsField = DcerpcMessage.class.getDeclaredField("flags");
        flagsField.setAccessible(true);
        int flagsValue = (int) flagsField.get(request);
        int expectedFlags = DcerpcConstants.DCERPC_FIRST_FRAG | DcerpcConstants.DCERPC_LAST_FRAG;
        assertEquals(expectedFlags, flagsValue, "The 'flags' field should be initialized to DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG.");
    }
}