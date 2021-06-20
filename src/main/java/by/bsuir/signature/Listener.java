package by.bsuir.signature;

import java.math.BigInteger;

public interface Listener {

    void showSign(BigInteger r, BigInteger s, BigInteger hash);

}
