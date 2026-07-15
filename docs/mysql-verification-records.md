# MySQL verification record storage

## 1. Create database and table

Open Navicat, connect to local MySQL, and run:

```sql
source scripts/mysql/verification-records.sql;
```

If Navicat does not allow `source`, open `scripts/mysql/verification-records.sql` and run the SQL content directly.

## 2. Enable MySQL storage

PowerShell example:

```powershell
$env:VERIFICATION_RECORDS_STORAGE="mysql"
$env:VERIFICATION_RECORDS_MYSQL_URL="jdbc:mysql://127.0.0.1:3306/traffic_verification?useUnicode=true&characterEncoding=utf8&serverTimezone=Asia/Shanghai&useSSL=false&allowPublicKeyRetrieval=true"
$env:VERIFICATION_RECORDS_MYSQL_USERNAME="root"
$env:VERIFICATION_RECORDS_MYSQL_PASSWORD="your_password"
mvn -q spring-boot:run
```

`verification.records.mysql.initialize-schema` defaults to `true`, so the backend can also create the table automatically after the database exists.

## 3. Verify

Run any Merkle, ZKP, or threshold-signature verification request, then check:

```sql
SELECT record_id, verify_type, business_id, status, ledger_status, created_at
FROM verification_records
ORDER BY created_at DESC
LIMIT 20;
```

The existing list and detail APIs keep the same paths:

```text
GET /api/cross-verification/records?page=1&size=10
GET /api/cross-verification/records/{recordId}
```

If `VERIFICATION_RECORDS_STORAGE` is not set to `mysql`, the service keeps the previous in-memory behavior.
