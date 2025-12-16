package com.project021.demo1.controller;

import com.project021.demo1.database.Database;
import com.project021.demo1.model.User;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.stage.Stage;

import java.util.logging.Level;
import java.util.logging.Logger;

public class AuthController {
    @FXML private TextField usernameField;
    @FXML private PasswordField passwordField;

    private final Database database = new Database();

    private static final Logger logger = Logger.getLogger(AuthController.class.getName());

    @FXML
    private void handleLogin() {
        String username = usernameField.getText().trim();
        String password = passwordField.getText().trim();

        if (username.isEmpty() || password.isEmpty()) {
            showAlert("Please fill all fields!");
            return;
        }

        User user = database.authenticateUser(username, password);
        if (user != null) {
            openMainWindow(user);
            closeCurrentWindow();
        } else {
            showAlert("Invalid credentials!");
            passwordField.clear();
        }
    }

    private void showAlert(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    @FXML
    private void openRegisterWindow() {
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource(
                    "/com/project021/demo1/views/register.fxml"));
            Parent root = loader.load();
            Stage stage = new Stage();
            stage.setTitle("Registration");
            stage.setScene(new Scene(root));
            stage.show();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error loading registration window", e);
            showAlert("Error loading registration window: " + e.getMessage());
        }
    }

    private void openMainWindow(User user) {
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource(
                    "/com/project021/demo1/views/main.fxml"));
            Parent root = loader.load();
            MainController controller = loader.getController();
            controller.setCurrentUser(user);
            Stage stage = new Stage();
            stage.setTitle("Crypto App");
            stage.setScene(new Scene(root));
            stage.show();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error loading main window", e);
            showAlert("Error loading main window: " + e.getMessage());
        }
    }

    private void closeCurrentWindow() {
        ((Stage) usernameField.getScene().getWindow()).close();
    }
}
