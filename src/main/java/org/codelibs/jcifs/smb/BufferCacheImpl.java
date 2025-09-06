/*
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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

package org.codelibs.jcifs.smb;

import java.util.Arrays;

/**
 * Cache for reusable byte buffers
 *
 *
 * <p>This class is intended for internal use.</p>
 */
public class BufferCacheImpl implements BufferCache {

    private final Object[] cache;
    private final int bufferSize;
    private int freeBuffers = 0;

    /**
     * Constructs a buffer cache using configuration settings.
     *
     * @param cfg the configuration to use for buffer cache settings
     */
    public BufferCacheImpl(final Configuration cfg) {
        this(cfg.getBufferCacheSize(), cfg.getMaximumBufferSize());
    }

    /**
     * Constructs a buffer cache with specified parameters.
     *
     * @param maxBuffers the maximum number of buffers to cache
     * @param maxSize the size of each buffer in bytes
     *
     */
    public BufferCacheImpl(final int maxBuffers, final int maxSize) {
        this.cache = new Object[maxBuffers];
        this.bufferSize = maxSize;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.BufferCache#getBuffer()
     */
    @Override
    public byte[] getBuffer() {
        synchronized (this.cache) {
            byte[] buf;

            if (this.freeBuffers > 0) {
                for (int i = 0; i < this.cache.length; i++) {
                    if (this.cache[i] != null) {
                        buf = (byte[]) this.cache[i];
                        this.cache[i] = null;
                        this.freeBuffers--;
                        return buf;
                    }
                }
            }
            return new byte[this.bufferSize];
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.BufferCache#releaseBuffer(byte[])
     */
    @Override
    public void releaseBuffer(final byte[] buf) {
        if (buf == null) {
            return;
        }
        // better safe than sorry: prevent leaks if there is some out of bound access
        Arrays.fill(buf, (byte) 0);
        synchronized (this.cache) {
            if (this.freeBuffers < this.cache.length) {
                for (int i = 0; i < this.cache.length; i++) {
                    if (this.cache[i] == null) {
                        this.cache[i] = buf;
                        this.freeBuffers++;
                        return;
                    }
                }
            }
        }
    }
}
