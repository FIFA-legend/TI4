package by.bsuir.signature;

import java.math.BigInteger;

public class SHA1 {

    public BigInteger sha1(byte[] message) {
        int h0 = 0x67452301;
        int h1 = 0xEFCDAB89;
        int h2 = 0x98BADCFE;
        int h3 = 0x10325476;
        int h4 = 0xC3D2E1F0;
        long messageLength = message.length * 8L;
        int mod = (int) (messageLength % 512);
        int newSize;
        if (mod <= 448) {
            newSize = (448 - mod + 64) / 8;
        } else {
            newSize = (512 - mod + 512) / 8;
        }
        byte[] updatedMessage = new byte[message.length + newSize];
        System.arraycopy(message, 0, updatedMessage, 0, message.length);
        updatedMessage[message.length] = (byte) 0b10000000;
        updatedMessage[updatedMessage.length - 1] = (byte) messageLength;
        updatedMessage[updatedMessage.length - 2] = (byte) (messageLength >> 8);
        updatedMessage[updatedMessage.length - 3] = (byte) (messageLength >> 16);
        updatedMessage[updatedMessage.length - 4] = (byte) (messageLength >> 24);
        updatedMessage[updatedMessage.length - 5] = (byte) (messageLength >> 32);
        for (int i = 0; i < updatedMessage.length; i += 64) {
            byte[] temp = new byte[64];
            System.arraycopy(updatedMessage, i, temp, 0, 64);
            int[] w = new int[80];
            for (int j = 0, k = 0; k < 16; j += 4, k++) {
                int temp1 = temp[j] >= 0 ? ((int) temp[j]) << 24 : ((int) temp[j]) + 256 << 24;
                int temp2 = temp[j + 1] >= 0 ? ((int) temp[j + 1]) << 16 : ((int) temp[j + 1]) + 256 << 16;
                int temp3 = temp[j + 2] >= 0 ? ((int) temp[j + 2]) << 8 : ((int) temp[j + 2]) + 256 << 8;
                int temp4 = temp[j + 3] >= 0 ? ((int) temp[j + 3]) : ((int) temp[j + 3]) + 256;
                w[k] = temp1 + temp2 + temp3 + temp4;
            }
            for (int j = 16; j < 80; j++) {
                w[j] = leftRotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
            }
            int a = h0;
            int b = h1;
            int c = h2;
            int d = h3;
            int e = h4;
            for (int j = 0; j < 80; j++) {
                int f, k;
                if (j <= 19) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                } else if (j <= 39) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (j <= 59) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }
                int t = leftRotate(a, 5) + f + e + k + w[j];
                e = d;
                d = c;
                c = leftRotate(b, 30);
                b = a;
                a = t;
            }
            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
        }
        //System.out.println(Integer.toHexString(h0) + Integer.toHexString(h1) + Integer.toHexString(h2) + Integer.toHexString(h3) + Integer.toHexString(h4));
        return new BigInteger(1, hashToArray(h0, h1, h2, h3, h4));
    }

    private int leftRotate(int integer, int shift) {
        return (integer << shift) | (integer >>> (32 - shift));
    }

    private byte[] hashToArray(int h0, int h1, int h2, int h3, int h4) {
        byte[] bytes = new byte[20];
        bytes[0] = (byte) (h0 >> 24);
        bytes[1] = (byte) (h0 >> 16);
        bytes[2] = (byte) (h0 >> 8);
        bytes[3] = (byte) h0;
        bytes[4] = (byte) (h1 >> 24);
        bytes[5] = (byte) (h1 >> 16);
        bytes[6] = (byte) (h1 >> 8);
        bytes[7] = (byte) h1;
        bytes[8] = (byte) (h2 >> 24);
        bytes[9] = (byte) (h2 >> 16);
        bytes[10] = (byte) (h2 >> 8);
        bytes[11] = (byte) h2;
        bytes[12] = (byte) (h3 >> 24);
        bytes[13] = (byte) (h3 >> 16);
        bytes[14] = (byte) (h3 >> 8);
        bytes[15] = (byte) h3;
        bytes[16] = (byte) (h4 >> 24);
        bytes[17] = (byte) (h4 >> 16);
        bytes[18] = (byte) (h4 >> 8);
        bytes[19] = (byte) h4;
        return bytes;
    }

}