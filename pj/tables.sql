-- Drop existing tables if they exist
DROP TABLE IF EXISTS User;
DROP TABLE IF EXISTS HealthRecord;

-- Create User table
CREATE TABLE User (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password BLOB,
    `group` VARCHAR(1) -- Assuming 'H' or 'R' as the group values
);

-- Create HealthRecord table
CREATE TABLE HealthRecord (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    age INTEGER,
    gender VARCHAR(20),
    weight FLOAT,
    height FLOAT,
    health_history VARCHAR(100)
);
