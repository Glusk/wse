package com.github.glusk2.wse.common.crypto.util.md;

import static org.junit.Assert.*;

import java.security.MessageDigest;

import org.junit.Test;

import com.github.glusk2.wse.common.crypto.util.hashing.ImdSimpleCopy;
import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;

public class ImdSimpleCopyTest {

    @Test
    public void testImdSimpleCopy() {
        try {
            new ImdSimpleCopy(MessageDigest.getInstance("SHA-1"));
        } catch (Exception e) {
            fail("Test failed" + e.getMessage());
        }
    }

    @Test
    public void testDigest() {
        try {
            byte[] input = { 1, 2, 3, 4 };

            MessageDigest md = MessageDigest.getInstance("SHA-1");
            ImmutableMessageDigest imd = 
                new ImdSimpleCopy(
                    MessageDigest.getInstance("SHA-1")
                );
            
            md.update(input, 0, input.length);
            imd = imd.update(input, 0, input.length);
            

            assertArrayEquals(md.digest(), imd.digest());
        } catch (Exception e) {
            fail("Test failed" + e.getMessage());
        }
    }

    @Test
    public void testUpdate() {
        try {
            byte[] input = { 1, 2, 3, 4 };

            MessageDigest md = MessageDigest.getInstance("SHA-1");
            ImmutableMessageDigest imd = 
                new ImdSimpleCopy(
                    MessageDigest.getInstance("SHA-1")
                );

            md.update(input, 0, input.length);
            md.update(input, 0, input.length);

            imd = imd.update(input, 0, input.length)
                     .update(input, 0, input.length);

            assertArrayEquals(md.digest(), imd.digest());
        } catch (Exception e) {
            fail("Test failed" + e.getMessage());
        }
    }

}
