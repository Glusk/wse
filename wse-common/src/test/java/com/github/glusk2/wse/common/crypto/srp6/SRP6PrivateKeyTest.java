package com.github.glusk2.wse.common.crypto.srp6;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_s;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_x;
import com.github.glusk2.wse.common.crypto.util.hashing.ImdSimpleCopy;
import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;
import com.github.glusk2.wse.common.util.Mapping;

public class SRP6PrivateKeyTest {
    @Test
    public void testRFC5054() {
        ImmutableMessageDigest imd = null;
        try {
            imd = new ImdSimpleCopy(MessageDigest.getInstance("SHA-1"));
        } catch (NoSuchAlgorithmException nsae) {
            fail(nsae.getMessage());
        }
        final Mapping<byte[], SRP6Integer> rule = 
            new SRP6FromRawRule(20, ByteOrder.BIG_ENDIAN);
        
        assertTrue(
            "Computed value doesn't match the test vector.",
            new RFC5054TestVector_x().string().equals(
                new SRP6PrivateKey(
                    imd,
                    new RFC5054TestVector_s(),
                    "alice",
                    "password123",
                    rule
                ).string()
            )
        );
    }
    
    @Test
    public void test2() {
        ImmutableMessageDigest imd = null;
        try {
            imd = new ImdSimpleCopy(MessageDigest.getInstance("SHA-1"));
        } catch (NoSuchAlgorithmException nsae) {
            fail(nsae.getMessage());
        }
        final Mapping<byte[], SRP6Integer> rule = 
            new SRP6FromRawRule(20, ByteOrder.LITTLE_ENDIAN);
        // SHA-1("USER:USER")
        final SRP6Integer p = 
            new SRP6PrecomputedValue(
                "EB5D7590 55285597 CA115295 1A585A47 5E1CB1BD"
                .replaceAll(" ", ""),
                ByteOrder.LITTLE_ENDIAN
            );
        final SRP6Integer s = 
            new SRP6PrecomputedValue(
                ("0D4894AB B6F8C86B 33FC586D 161B16C9" +
                 "AE2588A3 378395B6 E2CBE36E 76B60F6A"
                ).replaceAll(" ", ""),
                ByteOrder.LITTLE_ENDIAN
            );
        final SRP6Integer x = 
            new SRP6PrecomputedValue(
                "611C7539 A20DC594 FBCC45A6 BDDABF4D 67645F52"
                .replaceAll(" ", ""),
                ByteOrder.LITTLE_ENDIAN
            );
        
        assertTrue(
            "Computed value doesn't match the test vector.",
            x.string().equals(
                new SRP6PrivateKey(imd, s, p, rule).string()
            )
        );
    }
}
