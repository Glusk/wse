package com.github.glusk2.wse.common.crypto.util.hashing;

import java.security.MessageDigest;

/**
 * A simple "copy-before-action" {@code ImmutableMessageDigest} object.
 */
public final class ImdSimpleCopy implements ImmutableMessageDigest {
    private final MessageDigest md;

    public ImdSimpleCopy(MessageDigest md) {
        this.md = md;
    }

    private static MessageDigest clone(final MessageDigest md) {
        try {
            return (MessageDigest) md.clone();
        } catch (CloneNotSupportedException cnse) {
            throw
                new RuntimeException(
                    String.format(
                        "Couldn't make digest of partial content - the " +
                        "underlying MessageDigest object: %s is not " +
                        "cloneable.",
                        md
                    ),
                    cnse
                );
        }
    }

    @Override
    public byte[] digest() {
        return clone(this.md).digest();
    }

    @Override
    public ImmutableMessageDigest update(
        final byte[] arr,
        final int offset,
        final int len
    ) {
        MessageDigest clone = clone(this.md);
        clone.update(arr, offset, len);
        return new ImdSimpleCopy(clone);
    }
}
