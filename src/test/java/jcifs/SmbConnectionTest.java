package jcifs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.times;

import org.junit.jupiter.api.Test;

/**
 * Tests that {@link SmbConnection#getBatchLimit} uses the correct logic path.
 * The tests avoid reliance on internal default values by stubbing
 * {@link Configuration#getMaxBatchLimit()} and {@link Configuration#isUseUnicode()}
 * and by asserting the returned batch size directly.
 */
public class SmbConnectionTest {

    /**
     * When Unicode is enabled and batching is enabled, the method should
     * delegate to the configuration's {@code getMaxBatchLimit} value.
     */
    @Test
    public void testBatchLimitUsesConfigWhenUnicodeAndBatching() {
        Configuration cfg = mock(Configuration.class);
        when(cfg.isUseUnicode()).thenReturn(true);
        when(cfg.isUseBatching()).thenReturn(true);
        when(cfg.getMaxBatchLimit()).thenReturn(42);
        SmbConnection conn = new SmbConnection(cfg);
        int limit = conn.getBatchLimit(SmbConstants.SMB_COM_TRANSACTION, 0, 0);
        assertEquals(42, limit, "Batch limit should come from config when Unicode/Batching enabled");
    }

    /**
     * When Unicode is enabled but batching is disabled, the special
     * TreeConnectAndX.QueryInformation command should still return the
     * configured zero batch limit, while other commands default to one.
     */
    @Test
    public void testTreeConnectBatchLimitZeroWhenBatchingDisabled() {
        Configuration cfg = mock(Configuration.class);
        when(cfg.isUseUnicode()).thenReturn(true);
        when(cfg.isUseBatching()).thenReturn(false);
        SmbConnection conn = new SmbConnection(cfg);
        // this command is in DEFAULT_BATCH_LIMITS map with value 0
        int zeroLimit = conn.getBatchLimit(SmbConstants.SMB_COM_TREE_CONNECT_ANDX, 0, 0);
        assertEquals(0, zeroLimit, "TreeConnect should return 0 batch limit");
        // non-special command returns default 1
        int defaultLimit = conn.getBatchLimit(SmbConstants.SMB_COM_CREATE_DIRECTORY, 0, 0);
        assertEquals(1, defaultLimit, "Non-special command should default to 1");
    }

    /**
     * When Unicode is disabled, the configuration should not be consulted
     * for the batch limit.  We verify that the configuration's
     * {@code getMaxBatchLimit} is never called.
     */
    @Test
    public void testNoConfigCallWhenNotUnicode() {
        Configuration cfg = mock(Configuration.class);
        when(cfg.isUseUnicode()).thenReturn(false);
        // Even if batching true, method should not call getMaxBatchLimit
        when(cfg.isUseBatching()).thenReturn(true);
        SmbConnection conn = new SmbConnection(cfg);
        int limit = conn.getBatchLimit(SmbConstants.SMB_COM_TRANSACTION, 0, 0);
        // Under default implementation, the limit should be 1
        assertEquals(1, limit, "Non-unicode path returns default 1");
        verifyNoInteractions(cfg);
    }
}

