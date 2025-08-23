/*
 * © 2025 CodeLibs, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package jcifs.internal.smb2.rdma;

/**
 * RDMA credit management for flow control.
 *
 * Credits are used to control the flow of messages between
 * RDMA peers to prevent buffer overflow.
 */
public class RdmaCredits {

    private int initialCredits;
    private int creditsGranted;

    /**
     * Create new RDMA credits manager
     */
    public RdmaCredits() {
        this.initialCredits = RdmaCapabilities.DEFAULT_SEND_CREDIT_TARGET;
        this.creditsGranted = 0;
    }

    /**
     * Get initial number of credits to request
     *
     * @return initial credits
     */
    public int getInitialCredits() {
        return initialCredits;
    }

    /**
     * Set initial credits
     *
     * @param initialCredits initial credits to request
     */
    public void setInitialCredits(int initialCredits) {
        this.initialCredits = initialCredits;
    }

    /**
     * Get number of credits granted by peer
     *
     * @return granted credits
     */
    public int getCreditsGranted() {
        return creditsGranted;
    }

    /**
     * Set number of credits granted by peer
     *
     * @param creditsGranted credits granted
     */
    public void setCreditsGranted(int creditsGranted) {
        this.creditsGranted = creditsGranted;
    }
}
