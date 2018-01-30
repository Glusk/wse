package com.github.glusk2.wse.common.crypto.srp6;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_A;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_B;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.RFC5054TestVector_u;
import com.github.glusk2.wse.common.crypto.util.hashing.ImdSimpleCopy;
import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;
import com.github.glusk2.wse.common.util.Mapping;

public class SRP6ScrParTest {
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
            new RFC5054TestVector_u().string().equals(
                new SRP6ScrPar(
                    imd,
                    new RFC5054TestVector_A(),
                    new RFC5054TestVector_B(),
                    rule
                ).string()
            )
        );
    }
}
