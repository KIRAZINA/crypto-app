# 📌 Crypto App — JavaFX Encryption Tool

A desktop application built with **JavaFX**, **SQLite**, and **Java Cryptography Architecture (JCA)**.  
It provides user authentication, secure key storage, and text encryption/decryption using multiple algorithms.

This project is designed as a clean, modular Java application suitable for learning, portfolio use, or further extension.

---

## 🚀 Features

### 🔐 User Authentication
- Registration with **BCrypt** password hashing
- Login with validation
- Per‑user cryptographic keys stored securely in the database

### 🔑 Cryptography
The app supports three encryption algorithms:

- **AES** (128‑bit)
- **RSA** (2048‑bit)
- **Blowfish** (128‑bit)

Each user receives:
- A **master AES key**
- Encrypted AES, RSA, and Blowfish keys stored in SQLite
- Automatic key generation on first login

### 🧩 UI (JavaFX)
- Login window
- Registration window
- Main encryption/decryption interface
- Dark theme with modern styling
- Copy‑to‑clipboard buttons

### 🗄 Database
- SQLite local database
- Automatic schema creation
- Secure storage of encrypted keys

---

## 🛠 Technologies Used

| Component | Technology |
|----------|------------|
| UI | JavaFX 17 |
| Build Tool | Maven |
| Database | SQLite (sqlite‑jdbc) |
| Password Hashing | BCrypt |
| Cryptography | AES, RSA, Blowfish (JCA) |
| Language Level | Java 17 |

---

## 📂 Project Structure

```
src/
 └── main/
      ├── java/com/project021/demo1/
      │     ├── MainApp.java
      │     ├── controller/
      │     ├── database/
      │     └── model/
      └── resources/com/project021/demo1/
            ├── views/*.fxml
            └── database.properties
```

---

## ⚙️ Setup & Running

### 1. Install Requirements
- Java **17**
- Maven **3.8+**

### 2. Create the configuration file

The application requires a file:

```
src/main/resources/com/project021/demo1/database.properties
```

This file **must exist** and contain at least:

```
db.driver=org.sqlite.JDBC
db.url=jdbc:sqlite:crypto.db
db.schema.version=1
```

> ⚠️ The file is intentionally **not included** in the repository.  
> You must create it manually before running the application.

### 3. Run the application

Use Maven:

```
mvn clean javafx:run
```

---

## 🧪 Testing

JUnit 5 is included.  
Run tests with:

```
mvn test
```

---

## 📌 Notes & Limitations

- AES/ECB mode is used for simplicity; not recommended for production systems.
- SQLite database is unencrypted.
- Master key is stored in the database for demonstration purposes.
- This project is intended for educational and portfolio use.
