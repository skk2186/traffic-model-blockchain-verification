CREATE DATABASE IF NOT EXISTS traffic_verification
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE traffic_verification;

CREATE TABLE IF NOT EXISTS verification_records (
  record_id VARCHAR(96) NOT NULL PRIMARY KEY,
  verify_type VARCHAR(64) NOT NULL,
  verify_name VARCHAR(128) NULL,
  business_id VARCHAR(191) NULL,
  algorithm VARCHAR(128) NULL,
  status VARCHAR(32) NULL,
  result_hash VARCHAR(128) NULL,
  ledger_status VARCHAR(32) NULL,
  chain_path VARCHAR(255) NULL,
  resource_path VARCHAR(255) NULL,
  tx_hash VARCHAR(255) NULL,
  cross_chain_status VARCHAR(32) NULL,
  cross_chain_tx_hash VARCHAR(255) NULL,
  input_hash VARCHAR(128) NULL,
  proof_hash VARCHAR(128) NULL,
  detail_json LONGTEXT NULL,
  ledger_json LONGTEXT NULL,
  raw_result_json LONGTEXT NULL,
  created_at BIGINT NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_verify_records_created_at (created_at),
  INDEX idx_verify_records_type_status (verify_type, status),
  INDEX idx_verify_records_business_id (business_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
