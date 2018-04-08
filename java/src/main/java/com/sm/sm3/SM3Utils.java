package com.sm.sm3;

/**
 * SM3
 * @author William Sun
 */
public abstract class SM3Utils {

    //private
    private SM3Utils() {
    }
    //布尔函数
    public static int FF1j(int X, int Y, int Z) {
        return X ^ Y ^ Z;
    }

    public static int FF2j(int X, int Y, int Z) {
        return ((X & Y) | (X & Z) | (Y & Z));
    }

    public static int GG1j(int X, int Y, int Z) {
        return X ^ Y ^ Z;
    }

    public static int GG2j(int X, int Y, int Z) {
        return (X & Y) | (~X & Z);
    }

    
    public static byte[] back(byte[] in) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < out.length; i++) {
            out[i] = in[out.length - i - 1];
        }

        return out;
    }

    /**
     *
     */
    public static int bitCycleLeft(int n, int bitLen) {
        bitLen %= 32;
        byte[] tmp = bigEndianIntToByte(n);
        int byteLen = bitLen / 8;
        int len = bitLen % 8;
        if (byteLen > 0) {
            tmp = byteCycleLeft(tmp, byteLen);
        }

        if (len > 0) {
            tmp = bitSmall8CycleLeft(tmp, len);
        }

        return bigEndianByteToInt(tmp);
    }
    
    public static byte[] bitSmall8CycleLeft(byte[] in, int len) {
        byte[] tmp = new byte[in.length];
        int t1, t2, t3;
        for (int i = 0; i < tmp.length; i++) {
            t1 = (byte) ((in[i] & 0x000000ff) << len);
            t2 = (byte) ((in[(i + 1) % tmp.length] & 0x000000ff) >> (8 - len));
            t3 = (byte) (t1 | t2);
            tmp[i] = (byte) t3;
        }

        return tmp;
    }

   
    public static byte[] byteCycleLeft(byte[] in, int byteLen) {
        byte[] tmp = new byte[in.length];
        System.arraycopy(in, byteLen, tmp, 0, in.length - byteLen);
        System.arraycopy(in, 0, tmp, in.length - byteLen, byteLen);
        return tmp;
    }

 
    public static byte[] bigEndianIntToByte(int num) {
        return back(intToBytes(num));
    }

  
    public static int bigEndianByteToInt(byte[] bytes) {
        return byteToInt(back(bytes));
    }

    public static byte[] long2bytes(long l) {
        byte[] bytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) (l >>> ((7 - i) * 8));
        }
        return bytes;
    }


    public static int[] byteArrayConvertIntArray(byte[] arr) {
        int[] out = new int[arr.length / 4];
        byte[] tmp = new byte[4];
        for (int i = 0; i < arr.length; i += 4) {
            System.arraycopy(arr, i, tmp, 0, 4);
            out[i / 4] = bigEndianByteToInt(tmp);
        }
        return out;
    }
    public static byte[] intArrayConvertByteArray(int[] arr) {
        byte[] out = new byte[arr.length * 4];
        byte[] tmp;
        for (int i = 0; i < arr.length; i++) {
            tmp = bigEndianIntToByte(arr[i]);
            System.arraycopy(tmp, 0, out, i * 4, 4);
        }
        return out;
    }

 
    public static byte[] intToBytes(int num) {
        byte[] bytes = new byte[4];
        bytes[0] = (byte) (0xff & (num));
        bytes[1] = (byte) (0xff & (num >> 8));
        bytes[2] = (byte) (0xff & (num >> 16));
        bytes[3] = (byte) (0xff & (num >> 24));
        return bytes;
    }

    public static int byteToInt(byte[] bytes) {
        int num = 0;
        int temp;
        temp = (0x000000ff & (bytes[0]));
        num = num | temp;
        temp = (0x000000ff & (bytes[1])) << 8;
        num = num | temp;
        temp = (0x000000ff & (bytes[2])) << 16;
        num = num | temp;
        temp = (0x000000ff & (bytes[3])) << 24;
        num = num | temp;
        return num;
    }
}
