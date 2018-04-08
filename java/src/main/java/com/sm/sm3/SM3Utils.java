package com.sm.sm3;

/**
 * SM3算法实现需要的工具方法
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

    //数组翻转
    public static byte[] back(byte[] in) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < out.length; i++) {
            out[i] = in[out.length - i - 1];
        }

        return out;
    }

    /**
     * 循环左移
     * @param n 需要左移的数据
     * @param bitLen 移动位数
     * @return 移动后的结果
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
    //最低八位循环左移
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

    //循环左移的
    public static byte[] byteCycleLeft(byte[] in, int byteLen) {
        byte[] tmp = new byte[in.length];
        System.arraycopy(in, byteLen, tmp, 0, in.length - byteLen);
        System.arraycopy(in, 0, tmp, in.length - byteLen, byteLen);
        return tmp;
    }

    //高位int转化为byte数组
    public static byte[] bigEndianIntToByte(int num) {
        return back(intToBytes(num));
    }

    //高位ibyte数组转化为int
    public static int bigEndianByteToInt(byte[] bytes) {
        return byteToInt(back(bytes));
    }

    //long型转化为byte[]
    public static byte[] long2bytes(long l) {
        byte[] bytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) (l >>> ((7 - i) * 8));
        }
        return bytes;
    }


    //byte数组转化为int数组
    public static int[] byteArrayConvertIntArray(byte[] arr) {
        int[] out = new int[arr.length / 4];
        byte[] tmp = new byte[4];
        for (int i = 0; i < arr.length; i += 4) {
            System.arraycopy(arr, i, tmp, 0, 4);
            out[i / 4] = bigEndianByteToInt(tmp);
        }
        return out;
    }
    //int数组转化为byte数组
    public static byte[] intArrayConvertByteArray(int[] arr) {
        byte[] out = new byte[arr.length * 4];
        byte[] tmp;
        for (int i = 0; i < arr.length; i++) {
            tmp = bigEndianIntToByte(arr[i]);
            System.arraycopy(tmp, 0, out, i * 4, 4);
        }
        return out;
    }

    /**
     * int转化为byte数组
     * @param num 一个整型数据
     * @return 4个字节的自己数组
     */
    public static byte[] intToBytes(int num) {
        byte[] bytes = new byte[4];
        bytes[0] = (byte) (0xff & (num));
        bytes[1] = (byte) (0xff & (num >> 8));
        bytes[2] = (byte) (0xff & (num >> 16));
        bytes[3] = (byte) (0xff & (num >> 24));
        return bytes;
    }

    /**
     * @param bytes 4个字节的字节数组
     * @return 一个整型数据
     */
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
