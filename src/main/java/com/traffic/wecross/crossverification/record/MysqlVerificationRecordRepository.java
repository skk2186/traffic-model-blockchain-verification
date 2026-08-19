package com.traffic.wecross.crossverification.record;

import com.traffic.wecross.crossverification.dto.PageResult;
import com.traffic.wecross.crossverification.dto.VerificationResult;
import com.traffic.wecross.crossverification.ledger.LedgerSyncResult;
import com.traffic.wecross.crossverification.util.JsonUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Repository;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Repository
@ConditionalOnProperty(name = "verification.records.storage", havingValue = "mysql")
public class MysqlVerificationRecordRepository {
    private static final String CREATE_TABLE_SQL =
            "CREATE TABLE IF NOT EXISTS verification_records (" +
                    "record_id VARCHAR(96) NOT NULL PRIMARY KEY," +
                    "verify_type VARCHAR(64) NOT NULL," +
                    "verify_name VARCHAR(128) NULL," +
                    "business_id VARCHAR(191) NULL," +
                    "algorithm VARCHAR(128) NULL," +
                    "status VARCHAR(32) NULL," +
                    "result_hash VARCHAR(128) NULL," +
                    "ledger_status VARCHAR(32) NULL," +
                    "chain_path VARCHAR(255) NULL," +
                    "resource_path VARCHAR(255) NULL," +
                    "tx_hash VARCHAR(255) NULL," +
                    "cross_chain_status VARCHAR(32) NULL," +
                    "cross_chain_tx_hash VARCHAR(255) NULL," +
                    "input_hash VARCHAR(128) NULL," +
                    "proof_hash VARCHAR(128) NULL," +
                    "detail_json LONGTEXT NULL," +
                    "ledger_json LONGTEXT NULL," +
                    "raw_result_json LONGTEXT NULL," +
                    "created_at BIGINT NOT NULL," +
                    "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP," +
                    "INDEX idx_verify_records_created_at (created_at)," +
                    "INDEX idx_verify_records_type_status (verify_type, status)," +
                    "INDEX idx_verify_records_business_id (business_id)" +
                    ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

    private static final String UPSERT_SQL =
            "INSERT INTO verification_records (" +
                    "record_id, verify_type, verify_name, business_id, algorithm, status, result_hash," +
                    "ledger_status, chain_path, resource_path, tx_hash, cross_chain_status, cross_chain_tx_hash," +
                    "input_hash, proof_hash, detail_json, ledger_json, raw_result_json, created_at" +
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) " +
                    "ON DUPLICATE KEY UPDATE " +
                    "verify_type = VALUES(verify_type), " +
                    "verify_name = VALUES(verify_name), " +
                    "business_id = VALUES(business_id), " +
                    "algorithm = VALUES(algorithm), " +
                    "status = VALUES(status), " +
                    "result_hash = VALUES(result_hash), " +
                    "ledger_status = VALUES(ledger_status), " +
                    "chain_path = VALUES(chain_path), " +
                    "resource_path = VALUES(resource_path), " +
                    "tx_hash = VALUES(tx_hash), " +
                    "cross_chain_status = VALUES(cross_chain_status), " +
                    "cross_chain_tx_hash = VALUES(cross_chain_tx_hash), " +
                    "input_hash = VALUES(input_hash), " +
                    "proof_hash = VALUES(proof_hash), " +
                    "detail_json = VALUES(detail_json), " +
                    "ledger_json = VALUES(ledger_json), " +
                    "raw_result_json = VALUES(raw_result_json), " +
                    "created_at = VALUES(created_at)";

    private final String jdbcUrl;
    private final String username;
    private final String password;

    public MysqlVerificationRecordRepository(
            @Value("${verification.records.mysql.url:}") String jdbcUrl,
            @Value("${verification.records.mysql.username:}") String username,
            @Value("${verification.records.mysql.password:}") String password,
            @Value("${verification.records.mysql.initialize-schema:true}") boolean initializeSchema) {
        if (jdbcUrl == null || jdbcUrl.trim().isEmpty()) {
            throw new IllegalStateException(
                    "verification.records.storage=mysql requires verification.records.mysql.url");
        }
        this.jdbcUrl = jdbcUrl;
        this.username = username == null ? "" : username;
        this.password = password == null ? "" : password;
        loadDriver();
        if (initializeSchema) {
            initializeSchema();
        }
    }

    public void save(VerificationRecordDetail detail) {
        try (Connection connection = getConnection();
             PreparedStatement statement = connection.prepareStatement(UPSERT_SQL)) {
            bindRecord(statement, detail);
            statement.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Unable to save verification record to MySQL", e);
        }
    }

    public PageResult<VerificationRecord> listRecords(
            VerifyType verifyType,
            String businessId,
            VerifyStatus status,
            Integer page,
            Integer size) {
        int safePage = page == null || page < 1 ? 1 : page;
        int safeSize = size == null || size < 1 ? 10 : Math.min(size, 100);
        List<Object> params = new ArrayList<>();
        String whereSql = buildWhereSql(verifyType, businessId, status, params);
        long total = countRecords(whereSql, params);
        List<VerificationRecord> records = new ArrayList<>();
        String sql = "SELECT * FROM verification_records " + whereSql +
                " ORDER BY created_at DESC LIMIT ? OFFSET ?";
        try (Connection connection = getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            bindParams(statement, params);
            statement.setInt(params.size() + 1, safeSize);
            statement.setInt(params.size() + 2, (safePage - 1) * safeSize);
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    records.add(mapRecord(resultSet));
                }
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Unable to list verification records from MySQL", e);
        }
        return PageResult.of(records, safePage, safeSize, total);
    }

    public VerificationRecordDetail getRecordDetail(String recordId) {
        String sql = "SELECT * FROM verification_records WHERE record_id = ?";
        try (Connection connection = getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, recordId);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return null;
                }
                return mapDetail(resultSet);
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Unable to get verification record detail from MySQL", e);
        }
    }

    private void initializeSchema() {
        try (Connection connection = getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute(CREATE_TABLE_SQL);
        } catch (SQLException e) {
            throw new IllegalStateException("Unable to initialize verification_records table", e);
        }
    }

    private long countRecords(String whereSql, List<Object> params) {
        try (Connection connection = getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT COUNT(*) FROM verification_records " + whereSql)) {
            bindParams(statement, params);
            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSet.next() ? resultSet.getLong(1) : 0;
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Unable to count verification records from MySQL", e);
        }
    }

    private String buildWhereSql(
            VerifyType verifyType,
            String businessId,
            VerifyStatus status,
            List<Object> params) {
        StringBuilder sql = new StringBuilder("WHERE 1 = 1");
        if (verifyType != null) {
            sql.append(" AND verify_type = ?");
            params.add(verifyType.name());
        }
        if (status != null) {
            sql.append(" AND status = ?");
            params.add(status.name());
        }
        if (businessId != null && !businessId.trim().isEmpty()) {
            sql.append(" AND business_id = ?");
            params.add(businessId.trim());
        }
        return sql.toString();
    }

    private void bindParams(PreparedStatement statement, List<Object> params) throws SQLException {
        for (int i = 0; i < params.size(); i++) {
            statement.setObject(i + 1, params.get(i));
        }
    }

    private void bindRecord(PreparedStatement statement, VerificationRecordDetail detail) throws SQLException {
        statement.setString(1, detail.recordId);
        statement.setString(2, detail.verifyType);
        statement.setString(3, detail.verifyName);
        statement.setString(4, detail.businessId);
        statement.setString(5, detail.algorithm);
        statement.setString(6, detail.status);
        statement.setString(7, detail.resultHash);
        statement.setString(8, detail.ledgerStatus);
        statement.setString(9, detail.chainPath);
        statement.setString(10, detail.resourcePath);
        statement.setString(11, detail.txHash);
        statement.setString(12, detail.crossChainStatus);
        statement.setString(13, detail.crossChainTxHash);
        statement.setString(14, detail.inputHash);
        statement.setString(15, detail.proofHash);
        statement.setString(16, JsonUtils.toJson(detail.detail));
        statement.setString(17, JsonUtils.toJson(detail.ledger));
        statement.setString(18, JsonUtils.toJson(detail.rawResult));
        statement.setLong(19, detail.createdAt == null ? System.currentTimeMillis() : detail.createdAt);
    }

    private VerificationRecord mapRecord(ResultSet resultSet) throws SQLException {
        VerificationRecord record = new VerificationRecord();
        fillRecordFields(record, resultSet);
        return record;
    }

    private VerificationRecordDetail mapDetail(ResultSet resultSet) throws SQLException {
        VerificationRecordDetail detail = new VerificationRecordDetail();
        fillRecordFields(detail, resultSet);
        detail.inputHash = resultSet.getString("input_hash");
        detail.proofHash = resultSet.getString("proof_hash");
        detail.detail = JsonUtils.mapFromJson(resultSet.getString("detail_json"));
        detail.ledger = JsonUtils.fromJson(resultSet.getString("ledger_json"), LedgerSyncResult.class);
        detail.rawResult = JsonUtils.fromJson(resultSet.getString("raw_result_json"), VerificationResult.class);
        return detail;
    }

    private void fillRecordFields(VerificationRecord record, ResultSet resultSet) throws SQLException {
        record.recordId = resultSet.getString("record_id");
        record.verifyType = resultSet.getString("verify_type");
        record.verifyName = resultSet.getString("verify_name");
        record.businessId = resultSet.getString("business_id");
        record.algorithm = resultSet.getString("algorithm");
        record.status = resultSet.getString("status");
        record.resultHash = resultSet.getString("result_hash");
        record.ledgerStatus = resultSet.getString("ledger_status");
        record.chainPath = resultSet.getString("chain_path");
        record.resourcePath = resultSet.getString("resource_path");
        record.txHash = resultSet.getString("tx_hash");
        record.crossChainStatus = resultSet.getString("cross_chain_status");
        record.crossChainTxHash = resultSet.getString("cross_chain_tx_hash");
        record.createdAt = resultSet.getLong("created_at");
        if (resultSet.wasNull()) {
            record.createdAt = null;
        }
        Map<String, Object> detail = JsonUtils.mapFromJson(resultSet.getString("detail_json"));
        record.sourceChain = firstNonBlank(stringValue(detail.get("sourceChain")),
                chainFromPath(record.chainPath != null ? record.chainPath : record.resourcePath));
        record.verificationChain = stringValue(detail.get("verificationChain"));
        Object chainVerification = detail.get("chainVerification");
        if (chainVerification instanceof Map) {
            Map<?, ?> chain = (Map<?, ?>) chainVerification;
            record.sourceChain = firstNonBlank(stringValue(chain.get("sourceChain")), record.sourceChain);
            record.verificationChain = firstNonBlank(
                    stringValue(chain.get("verificationChain")), record.verificationChain);
        }
    }

    private String firstNonBlank(String value, String fallback) {
        return value != null && !value.trim().isEmpty() ? value : fallback;
    }

    private String stringValue(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private String chainFromPath(String path) {
        if (path == null) {
            return null;
        }
        String[] parts = path.split("\\.");
        return parts.length >= 2 ? parts[1] : null;
    }

    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection(jdbcUrl, username, password);
    }

    private void loadDriver() {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("MySQL JDBC driver is not available", e);
        }
    }
}
