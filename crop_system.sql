CREATE DATABASE IF NOT EXISTS crop_system
USE crop_system;

-- Users
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  full_name VARCHAR(100) NOT NULL,
  email VARCHAR(120) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Prediction history (optional but recommended)
CREATE TABLE IF NOT EXISTS predictions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  nitrogen FLOAT NOT NULL,
  phosphorus FLOAT NOT NULL,
  potassium FLOAT NOT NULL,
  temperature FLOAT NOT NULL,
  humidity FLOAT NOT NULL,
  ph FLOAT NOT NULL,
  rainfall FLOAT NOT NULL,
  predicted_crop VARCHAR(50) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Add columns for model predictions
ALTER TABLE predictions
ADD COLUMN rf_crop VARCHAR(50),
ADD COLUMN dt_crop VARCHAR(50),
ADD COLUMN svm_crop VARCHAR(50),
ADD COLUMN best_model VARCHAR(50);

ALTER TABLE users
  ADD COLUMN is_admin TINYINT(1) NOT NULL DEFAULT 0;

-- make yourself admin (change email)
UPDATE users SET is_admin = 1 WHERE email = 'sanyamkushwaha48@gmail.com';

