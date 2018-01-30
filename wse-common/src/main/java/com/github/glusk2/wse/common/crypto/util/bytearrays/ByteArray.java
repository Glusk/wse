package com.github.glusk2.wse.common.crypto.util.bytearrays;

public interface ByteArray {
	
    public byte[] array();
	
	public static final class WRAPPER implements ByteArray {
	    
	    private final byte[] arr;
	    
	    public WRAPPER(byte[] arr) {
            this.arr = arr;
        }
	    
        @Override
        public byte[] array() {
            return arr;
        }
	}
}
