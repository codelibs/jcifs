package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for the {@link AllocInfo} interface.
 * Since {@code AllocInfo} only declares getters, the tests focus on
 * verifying that implementations honour the contract.
 */
@ExtendWith(MockitoExtension.class)
public class AllocInfoTest {

    @Mock
    AllocInfo mockAllocInfo;

    /**
     * Happy path – verifies that getters return the values supplied by the
     * implementation.
     */
    @Test
    @DisplayName("verify getters return stubbed values")
    void testGettersHappyPath() {
        when(mockAllocInfo.getCapacity()).thenReturn(1000L);
        when(mockAllocInfo.getFree()).thenReturn(400L);

        assertEquals(1000L, mockAllocInfo.getCapacity(), "capacity should match stubbed value");
        assertEquals(400L, mockAllocInfo.getFree(), "free space should match stubbed value");
        verify(mockAllocInfo, times(1)).getCapacity();
        verify(mockAllocInfo, times(1)).getFree();
    }

    /**
     * Parameterised test of capacity values, including edge cases such as
     * zero and negative capacities.
     */
    @ParameterizedTest
    @ValueSource(longs = { 0L, -1L, Long.MAX_VALUE })
    @DisplayName("capacity may be any long value")
    void testCapacityEdgeValues(long capacity) {
        when(mockAllocInfo.getCapacity()).thenReturn(capacity);
        assertEquals(capacity, mockAllocInfo.getCapacity());
    }

    /**
     * Null pointer scenario – calls on a null reference should raise
     * {@link NullPointerException}. This test is defensive; in real code it
     * would likely be handled elsewhere.
     */
    @Test
    @DisplayName("calling getters on null reference throws NPE")
    void testNullReference() {
        AllocInfo nullRef = null;
        assertThrows(NullPointerException.class, () -> nullRef.getCapacity());
        assertThrows(NullPointerException.class, () -> nullRef.getFree());
    }
}
