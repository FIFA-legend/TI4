package by.bsuir.signature;

import by.bsuir.signature.exceptions.WrongFileException;
import by.bsuir.signature.exceptions.WrongResultException;
import by.bsuir.signature.exceptions.WrongValueException;

import java.io.*;
import java.math.BigInteger;
import java.util.Random;

public class DigitalSignature {

    private final BigInteger q;

    private final BigInteger p;

    private final BigInteger h;

    private final BigInteger x;

    private final BigInteger k;

    private final Listener listener;

    private static final BigInteger THREE = new BigInteger("3");

    public DigitalSignature(BigInteger q, BigInteger p, BigInteger h, BigInteger x, BigInteger k, Listener listener) {
        this.q = q;
        this.p = p;
        this.h = h;
        this.x = x;
        this.k = k;
        this.listener = listener;
    }

    public void signFile(File fileToSign) throws WrongValueException, WrongResultException {
        BigInteger g = powByMod(h, p.subtract(BigInteger.ONE).divide(q), p);
        if (g.min(BigInteger.ONE).equals(g)) throw new WrongValueException();
        BigInteger hash = fileHash(fileToSign, false);
        BigInteger r = powByMod(g, k, p).mod(q);
        BigInteger s = hash.add(x.multiply(r)).multiply(k.modPow(q.subtract(BigInteger.TWO), q)).mod(q);
        if (r.signum() == 0 || s.signum() == 0) throw new WrongResultException();
        rewriteFile(r, s, fileToSign);
        listener.showSign(r, s, hash);
    }

    public BigInteger[] checkSignature(File fileToCheck) throws WrongFileException {
        BigInteger g = powByMod(h, p.subtract(BigInteger.ONE).divide(q), p);
        BigInteger y = powByMod(g, x, p);
        try (BufferedReader br = new BufferedReader(new FileReader(fileToCheck))) {
            String line;
            String lastLine = null;
            while ((line = br.readLine()) != null) {
                lastLine = line;
            }
            if (lastLine != null) {
                String[] numbers;
                BigInteger r;
                BigInteger s;
                try {
                    numbers = lastLine.split(",");
                    r = new BigInteger(numbers[0]);
                    s = new BigInteger(numbers[1]);
                } catch (Exception e) {
                    throw new WrongFileException();
                }
                BigInteger w = powByMod(s, q.subtract(BigInteger.TWO), q);
                BigInteger hash = fileHash(fileToCheck, true);
                BigInteger u1 = hash.multiply(w).mod(q);
                BigInteger u2 = r.multiply(w).mod(q);
                BigInteger v = powByMod(g, u1, p).multiply(powByMod(y, u2, p)).mod(p).mod(q);
                return new BigInteger[]{r, v, hash};
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new BigInteger[0];
    }

    private void rewriteFile(BigInteger r, BigInteger s, File file) {
        try (DataInputStream dis = new DataInputStream(new FileInputStream(file));
             DataOutputStream dos = new DataOutputStream(new FileOutputStream(getSignedFile(file)))) {
            byte[] b = new byte[1024 * 1024];
            int count;
            do {
                count = dis.read(b);
                if (count > 0) {
                    dos.write(b, 0, count);
                }
            } while (dis.available() != 0);
        } catch (IOException e) {
            e.printStackTrace();
        }
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(getSignedFile(file), true))) {
            bw.write("\n" + r.toString() + "," + s.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private File getSignedFile(File file) {
        String path = file.getAbsolutePath();
        String pathToSignedFile = path.substring(0, path.lastIndexOf('.'));
        pathToSignedFile = pathToSignedFile.concat("(signed).txt");
        return new File(pathToSignedFile);
    }

    private BigInteger fileHash(File file, boolean isSigned) {
        try (DataInputStream dis = new DataInputStream(new FileInputStream(file))) {
            byte[] bytes = new byte[(int) file.length()];
            int count = dis.read(bytes);
            if (isSigned) {
                int temp = count;
                for (int i = count - 1; i >= 0; i--) {
                    if (bytes[i] == '\n') {
                        count = i;
                        break;
                    }
                }
                if (temp == count) count = 0;
            }
            SHA1 sha1 = new SHA1();
            byte[] message = new byte[count];
            System.arraycopy(bytes, 0, message, 0, count);
            return sha1.sha1(message);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /*private BigInteger fileHash(File file, boolean isSigned) {
        try (DataInputStream dis = new DataInputStream(new FileInputStream(file))) {
            BigInteger hash = new BigInteger("100");
            byte[] bytes = new byte[(int) file.length()];
            int count = dis.read(bytes);
            if (isSigned) {
                int temp = count;
                for (int i = count - 1; i >= 0; i--) {
                    if (bytes[i] == '\n') {
                        count = i;
                        break;
                    }
                }
                if (temp == count) count = 0;
            }
            hash = hash(hash, bytes, count);
            return hash;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private BigInteger hash(BigInteger previousHash, byte[] bytes, int toIndex) {
        for (int i = 0; i < toIndex; i++) {
            int charValue;
            if (bytes[i] < 0) charValue = bytes[i] + 256;
            else charValue = bytes[i];
            BigInteger m = new BigInteger(String.valueOf(charValue));
            previousHash = previousHash.add(m).pow(2).mod(q);
        }
        return previousHash;
    }*/

    private BigInteger powByMod(BigInteger a, BigInteger b, BigInteger m) {
        a = a.mod(m);
        BigInteger x = BigInteger.ONE;
        while (b.signum() != 0) {
            while (b.mod(BigInteger.TWO).signum() == 0) {
                b = b.divide(BigInteger.TWO);
                a = a.multiply(a).mod(m);
            }
            b = b.subtract(BigInteger.ONE);
            x = x.multiply(a).mod(m);
        }
        return x;
    }

    public static boolean isProbablePrime(BigInteger n, int k) {
        if (n.compareTo(BigInteger.ONE) == 0 || n.compareTo(BigInteger.ZERO) == 0)
            return false;
        if (n.compareTo(THREE) == 0 || n.compareTo(BigInteger.TWO) == 0)
            return true;
        int s = 0;
        BigInteger d = n.subtract(BigInteger.ONE);
        while (d.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            s++; // n-1 =2^s * d, d%2!=0
            d = d.divide(BigInteger.TWO);
        } // число составное если имеет место хотя бы одно из условий
        for (int i = 0; i < k; i++) {
            BigInteger a = uniformRandom(BigInteger.TWO, n.subtract(BigInteger.ONE)); // Выбрать случайное целое число a в отрезке [2, n − 1]
            BigInteger x = a.modPow(d, n); // a^d mod n != 1
            if (x.equals(BigInteger.ONE) || x.equals(n.subtract(BigInteger.ONE)))
                continue;
            int r = 0;
            for (; r < s; r++) { // E r<s a^((2^r)*d) mod n !=-1
                x = x.modPow(BigInteger.TWO, n);
                if (x.equals(BigInteger.ONE))
                    return false;
                if (x.equals(n.subtract(BigInteger.ONE)))
                    break;
            }
            if (r == s)
                return false;
        }
        return true;
    }

    private static BigInteger uniformRandom(BigInteger bottom, BigInteger top) {
        Random rnd = new Random();
        BigInteger res;
        do {
            res = new BigInteger(top.bitLength(), rnd);
        } while (res.compareTo(bottom) < 0 || res.compareTo(top) > 0);
        return res;
    }

}