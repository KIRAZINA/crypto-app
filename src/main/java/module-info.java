module com.project.demo {
    requires javafx.controls;
    requires javafx.fxml;
    requires java.desktop;
    requires java.xml;
    requires jbcrypt;
    requires java.sql;
    requires java.management;

    opens com.project021.demo1 to javafx.fxml;
    exports com.project021.demo1;
    exports com.project021.demo1.controller;
    opens com.project021.demo1.controller to javafx.fxml;
    exports com.project021.demo1.database;
    opens com.project021.demo1.database to javafx.fxml;
    exports com.project021.demo1.model;
    opens com.project021.demo1.model to javafx.fxml;
}