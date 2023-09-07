package com.groom.domain.business.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class BusinessRegisterRequest {
    private Long userId;
    private String businessName;
    private String businessNumber;
    private String phoneNumber;
    private String workStartDate;
    private String workFinishDate;
    private String workStartTime;
    private String workFinishTime;
    private String businessType;
    private String salaryType;
    private Integer salary;
    private String businessDetail;
    private String address;
    private Double latitude;
    private Double longitude;
    private String recruitState;
}
