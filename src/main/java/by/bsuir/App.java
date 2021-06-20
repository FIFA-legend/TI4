package by.bsuir;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

import java.io.IOException;

public class App extends Application {

    private static Stage stage;

    public static Stage getStage() {
        return stage;
    }

    @Override
    public void start(Stage st) throws IOException {
        stage = st;
        Scene scene = new Scene(loadFXML("main_window.fxml"));
        st.getIcons().add(new Image(App.class.getResourceAsStream("Icon.jpg")));
        st.setTitle("Шифрование");
        st.setResizable(false);
        st.setScene(scene);
        st.show();
    }

    private static Parent loadFXML(String fxml) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(App.class.getResource(fxml));
        return fxmlLoader.load();
    }

    public static void main(String[] args) {
        launch();
    }

}