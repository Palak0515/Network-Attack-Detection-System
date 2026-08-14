create database if not exists network_attack_db;
use network_attack_db;

create table if not exists predictions (
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
create table if not exists attack_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME,
    source_ip VARCHAR(50),
    dest_ip VARCHAR(50),
    attack_type VARCHAR(50),
    severity VARCHAR(20)
);
select * from predictions;
