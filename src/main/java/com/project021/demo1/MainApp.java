package com.project021.demo1;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class MainApp extends Application {
    @Override
    public void start(Stage primaryStage) throws Exception {
        Parent root = FXMLLoader.load(getClass().getResource("/com/project021/demo1/views/auth.fxml"));
        primaryStage.setTitle("Crypto App - Login");
        primaryStage.setScene(new Scene(root));
        primaryStage.show();

    }
    public static void main(String[] args) {
        launch(args);
    }
}