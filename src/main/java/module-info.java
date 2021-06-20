module by.bsuir {
    requires javafx.controls;
    requires javafx.fxml;
    requires commons.codec;

    opens by.bsuir to javafx.fxml;
    exports by.bsuir;
}