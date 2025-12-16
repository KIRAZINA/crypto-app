package com.project021.demo1.database;

import com.project021.demo1.model.User;
import org.mindrot.jbcrypt.BCrypt;
import com.project021.demo1.controller.MainController;

import java.io.InputStream;
import java.sql.*;
import java.util.Properties;

public class Database {
    private static String DB_URL;

    public Database() {
        try {
            InputStream input = Database.class.getResourceAsStream(
                    "/com/project021/demo1/database.properties");

            if (input == null) {
                throw new RuntimeException("Файл конфигурации не найден!");
            }

            Properties prop = new Properties();
            prop.load(input);

            DB_URL = prop.getProperty("db.url");
            Class.forName(prop.getProperty("db.driver"));

            initializeDatabase();

        } catch (Exception e) {
            throw new RuntimeException("Ошибка инициализации БД: " + e.getMessage(), e);
        }
    }

    private void initializeDatabase() {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement()) {

            stmt.execute("CREATE TABLE IF NOT EXISTS users (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "username TEXT UNIQUE NOT NULL," +
                    "password_hash TEXT NOT NULL," +
                    "aes_key TEXT," +
                    "rsa_public_key TEXT," +
                    "rsa_private_key TEXT," +
                    "blowfish_key TEXT," +
                    "master_key TEXT)");

        } catch (SQLException e) {
            throw new RuntimeException("Ошибка создания таблицы: " + e.getMessage());
        }
    }

    public void saveUserKeys(User user, String aesKey, String rsaPublicKey, String rsaPrivateKey, String blowfishKey) {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(
                     "UPDATE users SET aes_key = ?, rsa_public_key = ?, rsa_private_key = ?, blowfish_key = ? WHERE id = ?")) {
            pstmt.setString(1, aesKey);
            pstmt.setString(2, rsaPublicKey);
            pstmt.setString(3, rsaPrivateKey);
            pstmt.setString(4, blowfishKey);
            pstmt.setInt(5, user.getId());
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Error during user registration: " + e.getMessage());
        }
    }

    public void loadUserKeys(User user) {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(
                     "SELECT aes_key, rsa_public_key, rsa_private_key, blowfish_key FROM users WHERE id = ?")) {
            pstmt.setInt(1, user.getId());
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                user.setEncryptedAESKey(rs.getString("aes_key"));
                user.setEncryptedRSAPublicKey(rs.getString("rsa_public_key"));
                user.setEncryptedRSAPrivateKey(rs.getString("rsa_private_key"));
                user.setEncryptedBlowfishKey(rs.getString("blowfish_key"));
            }
        } catch (SQLException e) {
            System.err.println("Error during user registration: " + e.getMessage());
        }
    }

    public boolean registerUser(String username, String password) {
        String hash = BCrypt.hashpw(password, BCrypt.gensalt());

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(
                     "INSERT INTO users(username, password_hash) VALUES(?, ?)", Statement.RETURN_GENERATED_KEYS)) {

            pstmt.setString(1, username);
            pstmt.setString(2, hash);
            pstmt.executeUpdate();

            try (ResultSet generatedKeys = pstmt.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    int userId = generatedKeys.getInt(1);
                    User newUser = new User(userId, username, hash);
                    generateAndSaveInitialKeys(newUser);
                    return true;
                } else {
                    throw new SQLException("Creating user failed, no ID obtained.");
                }
            }

        } catch (SQLException e) {
            System.err.println("Error during user registration: " + e.getMessage());
            return false;
        }
    }


    private void generateAndSaveInitialKeys(User user) {
        try {
            MainController.generateInitialKeysAndSave(user, this);
        } catch (Exception e) {
            System.err.println("Error during user registration: " + e.getMessage());
        }
    }

    public User authenticateUser(String username, String password) {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(
                     "SELECT * FROM users WHERE username = ?")) {

            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next() && BCrypt.checkpw(password, rs.getString("password_hash"))) {
                return new User(
                        rs.getInt("id"),
                        rs.getString("username"),
                        rs.getString("password_hash")
                );
            }
        } catch (SQLException e) {
            System.err.println("Error during user registration: " + e.getMessage());
        }
        return null;
    }

    public String loadMasterKeyForUser(User user) {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement("SELECT master_key FROM users WHERE id = ?")) {
            stmt.setInt(1, user.getId());
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("master_key");
                }
            }
        } catch (SQLException e) {
            System.err.println("Error during user registration: " + e.getMessage());
        }
        return null;
    }

    public void saveMasterKeyForUser(User user, String encodedKey) {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement("UPDATE users SET master_key = ? WHERE id = ?")) {
            stmt.setString(1, encodedKey);
            stmt.setInt(2, user.getId());
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Error during user registration: " + e.getMessage());
        }
    }
}
