package com.project021.demo1.controller;

import com.project021.demo1.database.Database;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.stage.Stage;

public class RegisterController {
    @FXML private TextField usernameField;
    @FXML private PasswordField passwordField;
    @FXML private PasswordField confirmPasswordField;

    private final Database database = new Database();

    @FXML
    private void handleRegister() {
        String username = usernameField.getText().trim();
        String password = passwordField.getText().trim();
        String confirm = confirmPasswordField.getText().trim();

        if (username.isEmpty() || password.isEmpty()) {
            showAlert("Username and password cannot be empty!");
            return;
        }

        if (!password.equals(confirm)) {
            showAlert("Passwords do not match!");
            return;
        }

        if (database.registerUser(username, password)) {
            showSuccess("Registration successful!");
            closeWindow();
        } else {
            showAlert("Username already exists!");
        }
    }

    private void showAlert(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private void showSuccess(String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Success");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private void closeWindow() {
        ((Stage) usernameField.getScene().getWindow()).close();
    }
}
