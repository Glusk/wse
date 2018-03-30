package com.github.glusk2.wse.common.crypto.util.hashing;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.junit.Test;

public class HmacTest {

    @Test
    public void testOneRFC2104() {
        ImmutableMessageDigest imd = null;
        try {
            imd = new ImdSimpleCopy(MessageDigest.getInstance("MD5"));
        } catch (NoSuchAlgorithmException e) {
            fail(e.getMessage());
        }
        assertTrue(
            "Digest doesn't match the test vector.",
            Arrays.equals(
                new DigestArgument.BYTES(
                    "9294727a3638bb1c13f48ef8158bfc9d"
                ).bytes(),
                new Hmac(
                    imd,
                    new ValueExpansion((byte) 0x0b, 16),
                    new StringArgument("Hi There")
                ).bytes()
            )
        );
    }

    @Test
    public void testTwoRFC2104() {
        ImmutableMessageDigest imd = null;
        try {
            imd = new ImdSimpleCopy(MessageDigest.getInstance("MD5"));
        } catch (NoSuchAlgorithmException e) {
            fail(e.getMessage());
        }
        assertTrue(
            "Digest doesn't match the test vector.",
            Arrays.equals(
                new DigestArgument.BYTES(
                    "750c783e6ab0b503eaa86e310a5db738"
                ).bytes(),
                new Hmac(
                    imd,
                    new StringArgument("Jefe"),
                    new StringArgument("what do ya want for nothing?") 
                ).bytes()
            )
        );
    }

    @Test
    public void testThreeRFC2104() {
        ImmutableMessageDigest imd = null;
        try {
            imd = new ImdSimpleCopy(MessageDigest.getInstance("MD5"));
        } catch (NoSuchAlgorithmException e) {
            fail(e.getMessage());
        }
        assertTrue(
            "Digest doesn't match the test vector.",
            Arrays.equals(
                new DigestArgument.BYTES(
                    "56be34521d144c88dbb8c733f0e8b3f6"
                ).bytes(),
                new Hmac(
                    imd,
                    new ValueExpansion((byte) 0xaa, 16),
                    new ValueExpansion((byte) 0xdd, 50)
                ).bytes()
            )
        );
    }
}
