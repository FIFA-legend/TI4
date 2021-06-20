package by.bsuir;

import by.bsuir.signature.DigitalSignature;
import by.bsuir.signature.Listener;
import by.bsuir.signature.exceptions.WrongFileException;
import by.bsuir.signature.exceptions.WrongResultException;
import by.bsuir.signature.exceptions.WrongValueException;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;

import java.io.File;
import java.math.BigInteger;

public class MainWindowController {

    @FXML
    private TextField hField;

    @FXML
    private Button signButton;

    @FXML
    private TextField pathField;

    @FXML
    private Button checkButton;

    @FXML
    private Button fileButton;

    @FXML
    private TextArea logField;

    @FXML
    private TextField xField;

    @FXML
    private TextField kField;

    @FXML
    private TextField pField;

    @FXML
    private TextField qField;

    private File file;

    private final Listener listener = (r, s, hash) -> logField.setText(r + "," + s + "\nHash: " + hash);

    @FXML
    void initialize() {
        fileButton.setOnAction(actionEvent -> {
            FileChooser chooser = new FileChooser();
            file = chooser.showOpenDialog(App.getStage());
            if (file == null) {
                pathField.setText("");
            } else {
                pathField.setText(file.getAbsolutePath());
            }
        });

        signButton.setOnAction(actionEvent -> {
            if (file == null) {
                printFileNotFoundError();
            } else {
                BigInteger q = readQ();
                BigInteger p = readP();
                BigInteger h = readH();
                BigInteger x = readX();
                BigInteger k = readK();
                if (q != null && p != null && h != null && x != null && k != null) {
                    if (q.signum() <= 0 || p.signum() <= 0 || h.signum() <= 0 || x.signum() <= 0 || k.signum() <= 0) {
                        printNumberIsNegative();
                    } else if (!DigitalSignature.isProbablePrime(p, 10) || !DigitalSignature.isProbablePrime(q,10)) {
                        printNumberIsNotPrime();
                    } else if (p.subtract(BigInteger.ONE).mod(q).signum() != 0) {
                        printInvalidP();
                    } else if (!h.max(BigInteger.TWO).equals(h) || !h.min(p.subtract(BigInteger.TWO)).equals(h)) {
                        printInvalidH();
                    } else if (!x.max(BigInteger.ONE).equals(x) || !x.min(q.subtract(BigInteger.ONE)).equals(x)) {
                        printInvalidXorK("X");
                    } else if (!k.max(BigInteger.ONE).equals(k) || !k.min(q.subtract(BigInteger.ONE)).equals(k)) {
                        printInvalidXorK("K");
                    } else {
                        DigitalSignature signature = new DigitalSignature(q, p, h, x, k, listener);
                        try {
                            signature.signFile(file);
                            printFileSigned();
                        } catch (WrongValueException e) {
                            printInvalidG();
                        } catch (WrongResultException e) {
                            printInvalidSorR();
                        }
                    }
                }
            }
        });

        checkButton.setOnAction(actionEvent -> {
            if (file == null) {
                printFileNotFoundError();
            } else {
                BigInteger q = readQ();
                BigInteger p = readP();
                BigInteger h = readH();
                BigInteger x = readX();
                BigInteger k = readK();
                if (q != null && p != null && h != null && x != null && k != null) {
                    if (q.signum() <= 0 || p.signum() <= 0 || h.signum() <= 0 || x.signum() <= 0 || k.signum() <= 0) {
                        printNumberIsNegative();
                    } else if (!DigitalSignature.isProbablePrime(p, 10) || !DigitalSignature.isProbablePrime(q,10)) {
                        printNumberIsNotPrime();
                    } else if (p.subtract(BigInteger.ONE).mod(q).signum() != 0) {
                        printInvalidP();
                    } else if (!h.max(BigInteger.TWO).equals(h) || !h.min(p.subtract(BigInteger.TWO)).equals(h)) {
                        printInvalidH();
                    } else if (!x.max(BigInteger.ONE).equals(x) || !x.min(q.subtract(BigInteger.ONE)).equals(x)) {
                        printInvalidXorK("X");
                    } else if (!k.max(BigInteger.ONE).equals(k) || !k.min(q.subtract(BigInteger.ONE)).equals(k)) {
                        printInvalidXorK("K");
                    } else {
                        DigitalSignature signature = new DigitalSignature(q, p, h, x, k, listener);
                        try {
                            BigInteger[] numbers = signature.checkSignature(file);
                            if (numbers[0].equals(numbers[1])) {
                                printFileHasCorrectSign(numbers[0], numbers[1], numbers[2]);
                            } else {
                                printFileHasIncorrectSign(numbers[0], numbers[1], numbers[2]);
                            }
                        } catch (WrongFileException e) {
                            printFileNotSigned();
                        }
                    }
                }
            }
        });

    }

    private BigInteger readQ() {
        BigInteger q = null;
        try {
            q = new BigInteger(qField.getText());
        } catch (NumberFormatException e) {
            printNumberIsNotCorrect("Q");
        }
        return q;
    }

    private BigInteger readP() {
        BigInteger p = null;
        try {
            p = new BigInteger(pField.getText());
        } catch (NumberFormatException e) {
            printNumberIsNotCorrect("P");
        }
        return p;
    }

    private BigInteger readH() {
        BigInteger b = null;
        try {
            b = new BigInteger(hField.getText());
        } catch (NumberFormatException e) {
            printNumberIsNotCorrect("H");
        }
        return b;
    }

    private BigInteger readX() {
        BigInteger x = null;
        try {
            x = new BigInteger(xField.getText());
        } catch (NumberFormatException e) {
            printNumberIsNotCorrect("X");
        }
        return x;
    }

    private BigInteger readK() {
        BigInteger k = null;
        try {
            k = new BigInteger(kField.getText());
        } catch (NumberFormatException e) {
            printNumberIsNotCorrect("K");
        }
        return k;
    }

    private void printFileHasCorrectSign(BigInteger r, BigInteger v, BigInteger hash) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Information");
        alert.setHeaderText(null);
        alert.setContentText(r + "==" + v + "\nFile wasn't changed\n" + hash);
        alert.show();
    }

    private void printFileSigned() {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Information");
        alert.setHeaderText(null);
        alert.setContentText("File Signed Successfully");
        alert.show();
    }

    private void printFileHasIncorrectSign(BigInteger r, BigInteger v, BigInteger hash) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(null);
        alert.setContentText(r + "!=" + v + "\nFile was changed\n" + hash);
        alert.show();
    }

    private void printInvalidSorR() {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(null);
        alert.setContentText("R and S should not be 0");
        alert.show();
    }

    private void printInvalidG() {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(null);
        alert.setContentText("G should not equal 1");
        alert.show();
    }

    private void printInvalidXorK(String key) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(null);
        alert.setContentText(key + " should be greater than 0 and lower than Q");
        alert.show();
    }

    private void printInvalidH() {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(null);
        alert.setContentText("H should be greater than 1 and lower than (P - 1)");
        alert.show();
    }

    private void printInvalidP() {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(null);
        alert.setContentText("(P - 1) should be divided by Q");
        alert.show();
    }

    private void printNumberIsNotPrime() {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(null);
        alert.setContentText("Q, P Keys Should be Prime");
        alert.show();
    }

    private void printNumberIsNegative() {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(null);
        alert.setContentText("The Keys Can't be Negative");
        alert.show();
    }

    private void printNumberIsNotCorrect(String number) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(null);
        alert.setContentText(number + " Key Contains Invalid Symbols");
        alert.show();
    }

    private void printFileNotSigned() {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(null);
        alert.setContentText("The File is not Signed");
        alert.show();
    }

    private void printFileNotFoundError() {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(null);
        alert.setContentText("You Should Open a File");
        alert.show();
    }

}
