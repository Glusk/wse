package com.github.glusk2.wse.common.crypto.util.hashing;

/**
 * Extension of {@code MessageDigest} functionality that allows method chaining
 * and is immutable.
 */
public interface ImmutableMessageDigest {
    byte[] digest();
    
    ImmutableMessageDigest update(byte[] arr, int offset, int len);
    
    default ImmutableMessageDigest update(byte[] arr) {
        return update(arr, 0, arr.length);
    }
    
    default ImmutableMessageDigest update(DigestArgument... args) {
        ImmutableMessageDigest imd = this;
        for (DigestArgument arg : args) {
            imd = imd.update(arg.bytes());
        }
        return imd;
    }
}
