package com.sm;

import com.sm.sm2.SM2;
import com.sm.sm3.SM3;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.math.BigInteger;

/**
 * SM算法需要的一些工具方法
 *
 * @author William Sun
 */
public abstract class SMUtils {

    private static final char[] DIGITS_LOWER = {'0', '1', '2', '3', '4', '5',
            '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    private static final char[] DIGITS_UPPER = {'0', '1', '2', '3', '4', '5',
            '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};


    //十六进制的字符串
    private static final String HEX_CHARS = "0123456789ABCDEF";


    private SMUtils() {
    }


    /**
     * 获取签名/验签所使用的Z值
     *
     * @param userId  用户标识
     * @param userKey ECPoint
     * @param sm2     SM2 instance
     * @return Z
     * @throws IOException
     */
    public static byte[] sm2GetZ(byte[] userId, ECPoint userKey, SM2 sm2) throws IOException {

        int entLen = userId.length * 8;
        byte[] ENTL = new byte[2];
        ENTL[0] = (byte) (entLen >> 8 & 0xFF);
        ENTL[1] = (byte) (entLen & 0xFF);

        byte[] a = byteConvert32Bytes(sm2.getEcc_a());
        byte[] b = byteConvert32Bytes(sm2.getEcc_b());
        byte[] gx = byteConvert32Bytes(sm2.getEcc_gx());
        byte[] gy = byteConvert32Bytes(sm2.getEcc_gy());
        byte[] x = byteConvert32Bytes(userKey.normalize().getXCoord().toBigInteger());
        byte[] y = byteConvert32Bytes(userKey.normalize().getYCoord().toBigInteger());

        int tempLen = 2 + userId.length + a.length + b.length + gx.length + gy.length + x.length + y.length;
        byte[] temp = new byte[tempLen];

        System.arraycopy(ENTL, 0, temp, 0, ENTL.length);
        System.arraycopy(userId, 0, temp, ENTL.length, userId.length);
        System.arraycopy(a, 0, temp, ENTL.length + userId.length, a.length);
        System.arraycopy(b, 0, temp, ENTL.length + userId.length + a.length, b.length);
        System.arraycopy(gx, 0, temp, ENTL.length + userId.length + a.length + b.length, gx.length);
        System.arraycopy(gy, 0, temp, ENTL.length + userId.length + a.length + b.length + gx.length, gy.length);
        System.arraycopy(x, 0, temp, ENTL.length + userId.length + a.length + b.length + gx.length + gy.length, x.length);
        System.arraycopy(y, 0, temp, ENTL.length + userId.length + a.length + b.length + gx.length + gy.length + x.length, y.length);

        return SM3.hash(temp);
    }


    /**
     * int 转化为 byte 数组
     *
     * @param num 一个整型数据
     * @return 4个字节的字节数组
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

    /**
     * @param num 一个长整型数据
     * @return 4个字节的字节数组
     */
    public static byte[] longToBytes(long num) {

        byte[] bytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) (0xff & (num >> (i * 8)));
        }

        return bytes;
    }


    public static byte[] byteConvert32Bytes(BigInteger n) {

        byte tmpd[];
        if (n == null) {

            return null;
        }

        if (n.toByteArray().length == 33) {

            tmpd = new byte[32];
            System.arraycopy(n.toByteArray(), 1, tmpd, 0, 32);
        } else if (n.toByteArray().length == 32) {

            tmpd = n.toByteArray();
        } else {

            tmpd = new byte[32];
            for (int i = 0; i < 32 - n.toByteArray().length; i++) {

                tmpd[i] = 0;
            }
            System.arraycopy(n.toByteArray(), 0, tmpd, 32 - n.toByteArray().length, n.toByteArray().length);
        }
        return tmpd;
    }

    public static BigInteger byteConvertInteger(byte[] b) {
        if (b[0] < 0) {

            byte[] temp = new byte[b.length + 1];
            temp[0] = 0;
            System.arraycopy(b, 0, temp, 1, b.length);
            return new BigInteger(temp);
        }
        return new BigInteger(b);
    }

    public static String getHexString(byte[] bytes) {

        return getHexString(bytes, true);
    }

    public static String getHexString(byte[] bytes, boolean upperCase) {

        String ret = "";
        for (byte aByte : bytes) {

            ret += Integer.toString((aByte & 0xff) + 0x100, 16).substring(1);
        }
        return upperCase ? ret.toUpperCase() : ret;
    }

    public static byte[] hexStringToBytes(String hexString) {
        if (hexString == null || hexString.equals("")) {
            return null;
        }

        hexString = hexString.toUpperCase();
        int length = hexString.length() / 2;
        char[] hexChars = hexString.toCharArray();
        byte[] d = new byte[length];
        for (int i = 0; i < length; i++) {
            int pos = i * 2;
            d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
        }
        return d;
    }

    public static byte charToByte(char c) {

        return (byte) HEX_CHARS.indexOf(c);
    }


    /**
     * @param data byte[]
     * @return 十六进制char[]
     */
    public static char[] encodeHex(byte[] data) {

        return encodeHex(data, true);
    }

    /**
     * @param data        byte[]
     * @param toLowerCase <code>true</code> 传换成小写格式 ， <code>false</code> 传换成大写格式
     * @return 十六进制char[]
     */
    public static char[] encodeHex(byte[] data, boolean toLowerCase) {

        return encodeHex(data, toLowerCase ? DIGITS_LOWER : DIGITS_UPPER);
    }

    /**
     * @param data     byte[]
     * @param toDigits 用于控制输出的char[]
     * @return 十六进制char[]
     */
    protected static char[] encodeHex(byte[] data, char[] toDigits) {
        int l = data.length;
        char[] out = new char[l << 1];

        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = toDigits[(0xF0 & data[i]) >>> 4];
            out[j++] = toDigits[0x0F & data[i]];
        }
        return out;
    }

    /**
     * @param data byte[]
     * @return 十六进制String
     */
    public static String encodeHexString(byte[] data) {

        return encodeHexString(data, true);
    }

    /**
     * @param data        byte[]
     * @param toLowerCase <code>true</code> 传换成小写格式 ， <code>false</code> 传换成大写格式
     * @return 十六进制String
     */
    public static String encodeHexString(byte[] data, boolean toLowerCase) {

        return encodeHexString(data, toLowerCase ? DIGITS_LOWER : DIGITS_UPPER);
    }

    /**
     * @param data     byte[]
     * @param toDigits 用于控制输出的char[]
     * @return 十六进制String
     */
    protected static String encodeHexString(byte[] data, char[] toDigits) {

        return new String(encodeHex(data, toDigits));
    }

    /**
     * @param data 十六进制char[]
     * @return byte[]
     * @throws RuntimeException 如果源十六进制字符数组是一个奇怪的长度，将抛出运行时异常
     */
    public static byte[] decodeHex(char[] data) {

        int len = data.length;

        if ((len & 0x01) != 0) {
            throw new RuntimeException("Odd number of characters.");
        }

        byte[] out = new byte[len >> 1];

        // two characters form the hex value.
        for (int i = 0, j = 0; j < len; i++) {
            int f = toDigit(data[j], j) << 4;
            j++;
            f = f | toDigit(data[j], j);
            j++;
            out[i] = (byte) (f & 0xFF);
        }

        return out;
    }

    /**
     * @param ch    十六进制char
     * @param index 十六进制字符在字符数组中的位置
     * @return 一个整数
     * @throws RuntimeException 当ch不是一个合法的十六进制字符时，抛出运行时异常
     */
    protected static int toDigit(char ch, int index) {

        int digit = Character.digit(ch, 16);

        if (digit == -1) {
            throw new RuntimeException("Illegal hexadecimal character " + ch
                    + " at index " + index);
        }
        return digit;
    }


    /**
     * @return the array of byte
     */
    public static byte[] hexToByte(String hex) throws IllegalArgumentException {

        if (hex.length() % 2 != 0) {

            throw new IllegalArgumentException();
        }
        char[] arr = hex.toCharArray();
        byte[] b = new byte[hex.length() / 2];

        for (int i = 0, j = 0, l = hex.length(); i < l; i++, j++) {
            String swap = "" + arr[i++] + arr[i];
            int byteint = Integer.parseInt(swap, 16) & 0xFF;
            b[j] = new Integer(byteint).byteValue();
        }
        return b;
    }

    /**
     * @param b byte[] 需要转换的字节数组
     * @return String 十六进制字符串
     */
    public static String byteToHex(byte b[]) {
        if (b == null) {
            throw new IllegalArgumentException(
                    "Argument b ( byte array ) is null! ");
        }

        String hs = "";
        String stmp;

        for (byte aB : b) {
            stmp = Integer.toHexString(aB & 0xff);
            if (stmp.length() == 1) {
                hs = hs + "0" + stmp;
            } else {
                hs = hs + stmp;
            }
        }
        return hs.toUpperCase();
    }


    /**
     * Decode base64
     *
     * @param code 待解码字符串；
     * @return 解码后的byte数组；
     */
    public static byte[] decodeBase64(String code) {
//        return Base64.decode(code);
        return java.util.Base64.getDecoder().decode(code);
    }

    /**
     * Encode to base64
     *
     * @param code 待编码的byte数组；
     * @return 编码后的字符串；
     */
    public static String encodeBase64(byte[] code) {
        return new String(Base64.encode(code));
    }

    /**
     * int 转化为 byt array
     *
     * @param k int型；
     * @return byte数组；
     */
    public static byte[] intToByteArray(int k) {
        return new byte[]{(byte) ((k >> 24) & 0xff),
                (byte) ((k >> 16) & 0xff), (byte) ((k >> 8) & 0xff),
                (byte) (k & 0xff)};
    }


    public static String hexToBase64(String hex) throws IOException {

        byte[] cipher = SMUtils.hexStringToBytes(hex);
        return SMUtils.encodeBase64(cipher);
    }


}
