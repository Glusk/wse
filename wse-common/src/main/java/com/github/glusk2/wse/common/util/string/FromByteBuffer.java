package com.github.glusk2.wse.common.util.string;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;

public final class FromByteBuffer implements CString {

    private final ByteBuffer buf;
    private final Charset charset;

    public FromByteBuffer(ByteBuffer buf, Charset charset) {
        this.buf = buf.slice();
        this.charset = charset;
    }

    @Override
    public String string() {
        byte[] bytes = bytes();
        return new String(Arrays.copyOf(bytes, bytes.length - 1), charset);
    }

    @Override
    public byte[] bytes() {
        ByteBuffer tmp = buf.duplicate();
        int i = 0;
        while (tmp.get(i) != 0) {
            i++;
        }
        tmp.position(0);
        byte[] cStrBuff = new byte[i + 1];
        tmp.get(cStrBuff);
        return cStrBuff;
    }
}
