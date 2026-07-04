package com.traffic.wecross.crossverification.controller;

import com.traffic.wecross.crossverification.dto.PageResult;
import com.traffic.wecross.crossverification.dto.LedgerUpdateRequest;
import com.traffic.wecross.crossverification.record.VerificationRecord;
import com.traffic.wecross.crossverification.record.VerificationRecordDetail;
import com.traffic.wecross.crossverification.record.VerifyStatus;
import com.traffic.wecross.crossverification.record.VerifyType;
import com.traffic.wecross.crossverification.service.VerificationRecordService;
import com.traffic.wecross.crossverification.util.ErrorResultFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin
@RequestMapping("/api/cross-verification/records")
public class VerificationRecordController {
    private final VerificationRecordService verificationRecordService;

    public VerificationRecordController(VerificationRecordService verificationRecordService) {
        this.verificationRecordService = verificationRecordService;
    }

    @GetMapping
    public PageResult<VerificationRecord> listRecords(
            @RequestParam(required = false) VerifyType verifyType,
            @RequestParam(required = false) String businessId,
            @RequestParam(required = false) VerifyStatus status,
            @RequestParam(defaultValue = "1") Integer page,
            @RequestParam(defaultValue = "10") Integer size) {
        return verificationRecordService.listRecords(verifyType, businessId, status, page, size);
    }

    @GetMapping("/{recordId}")
    public ResponseEntity<?> getRecord(@PathVariable String recordId) {
        VerificationRecordDetail detail = verificationRecordService.getRecordDetail(recordId);
        if (detail == null) {
            return ResponseEntity.status(404).body(ErrorResultFactory.error(
                    null,
                    recordId,
                    "验证记录不存在",
                    "RECORD_NOT_FOUND"));
        }
        return ResponseEntity.ok(detail);
    }

    @PutMapping("/{recordId}/ledger")
    public ResponseEntity<?> updateLedger(
            @PathVariable String recordId,
            @RequestBody LedgerUpdateRequest request) {
        VerificationRecordDetail detail = verificationRecordService.getRecordDetail(recordId);
        if (detail == null) {
            return ResponseEntity.status(404).body(ErrorResultFactory.error(
                    null, recordId, "验证记录不存在", "RECORD_NOT_FOUND"));
        }
        if (request == null || request.ledger == null) {
            return ResponseEntity.badRequest().body(ErrorResultFactory.error(
                    null, recordId, "ledger 不能为空", "INVALID_LEDGER_UPDATE"));
        }
        verificationRecordService.updateLedger(recordId, request.ledger, request.chainVerification);
        return ResponseEntity.ok(verificationRecordService.getRecordDetail(recordId));
    }
}
