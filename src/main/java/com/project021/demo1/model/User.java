package com.project021.demo1.model;

import java.util.Objects;

public class User {
    private final int id;
    private final String username;
    private final String passwordHash;
    private String encryptedAESKey;
    private String encryptedRSAPublicKey;
    private String encryptedRSAPrivateKey;
    private String encryptedBlowfishKey;

    public User() {
        this.id = 0;
        this.username = null;
        this.passwordHash = null;
    }

    public User(int id, String username, String passwordHash) {
        validateUsername(username);
        validatePasswordHash(passwordHash);
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
    }


    private void validateUsername(String username) {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }
    }


    private void validatePasswordHash(String passwordHash) {
        if (passwordHash == null || passwordHash.trim().isEmpty()) {
            throw new IllegalArgumentException("Password hash cannot be null or empty");
        }
    }

    public int getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public String getEncryptedAESKey() {
        return encryptedAESKey;
    }

    public String getEncryptedRSAPublicKey() {
        return encryptedRSAPublicKey;
    }

    public String getEncryptedRSAPrivateKey() {
        return encryptedRSAPrivateKey;
    }

    public String getEncryptedBlowfishKey() {
        return encryptedBlowfishKey;
    }

    public void setEncryptedAESKey(String encryptedAESKey) {
        this.encryptedAESKey = encryptedAESKey;
    }

    public void setEncryptedRSAPublicKey(String encryptedRSAPublicKey) {
        this.encryptedRSAPublicKey = encryptedRSAPublicKey;
    }

    public void setEncryptedRSAPrivateKey(String encryptedRSAPrivateKey) {
        this.encryptedRSAPrivateKey = encryptedRSAPrivateKey;
    }

    public void setEncryptedBlowfishKey(String encryptedBlowfishKey) {
        this.encryptedBlowfishKey = encryptedBlowfishKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return id == user.id && Objects.equals(username, user.username);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, username);
    }

    @Override
    public String toString() {
        return "User{id=" + id + ", username='" + username + "'}";
    }
}