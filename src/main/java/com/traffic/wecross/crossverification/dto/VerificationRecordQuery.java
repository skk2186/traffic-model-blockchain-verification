package com.traffic.wecross.crossverification.dto;

import com.traffic.wecross.crossverification.record.VerifyStatus;
import com.traffic.wecross.crossverification.record.VerifyType;

public class VerificationRecordQuery {
    public VerifyType verifyType;
    public VerifyStatus status;
    public String businessId;
}
