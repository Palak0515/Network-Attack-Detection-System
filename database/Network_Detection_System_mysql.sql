CREATE DATABASE IF NOT EXISTS network_attack_db;
USE network_attack_db;

-- ----------------- Predictions Table (Used in your Flask code) -----------------
CREATE TABLE predictions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    duration FLOAT,
    src_bytes FLOAT,
    dst_bytes FLOAT,
    count FLOAT,
    same_srv_rate FLOAT,
    serror_rate FLOAT,
    flag FLOAT,
    logged_in FLOAT,
    result VARCHAR(10),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ----------------- CSV Logs Table (Optional Advanced Use) -----------------
CREATE TABLE IF NOT EXISTS attack_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME,
    source_ip VARCHAR(50),
    dest_ip VARCHAR(50),
    attack_type VARCHAR(50),
    severity VARCHAR(20)
);

-- ----------------- Check Data -----------------
SELECT * FROM predictions;

delete from predictions
where id>=45;