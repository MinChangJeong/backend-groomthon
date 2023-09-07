package com.groom.domain.business.service;

import com.groom.domain.business.dto.request.BusinessRegisterRequest;
import com.groom.domain.business.dto.response.*;
import com.groom.domain.business.entity.Business;
import com.groom.domain.business.repository.BusinessRepository;
import com.groom.domain.member.entity.Member;
import com.groom.domain.member.repository.MemberRepository;
import com.groom.global.advice.exception.EntityNotFoundException;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;


@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class BusinessService {
    BusinessRepository businessRepository;
    MemberRepository memberRepository;

    /*
    * 사업장 정보 등록
    * */
     public BusinessRegisterResponse registerBusiness(BusinessRegisterRequest request) {
         Member member = memberRepository.findById(request.getUserId()).orElseThrow(EntityNotFoundException::new);
         if(member.getUserType().equals("구직자")) {
             member.setUserType("구인자");
             memberRepository.save(member);
         }

         businessRepository.save(
                 Business.builder()
                         .member(member)
                         .businessName(request.getBusinessName())
                         .businessNumber(request.getBusinessNumber())
                         .phoneNumber(request.getPhoneNumber())
                         .workStartDate(request.getWorkStartDate())
                         .workFinishDate(request.getWorkFinishDate())
                         .workStartTime(request.getWorkStartTime())
                         .workFinishTime(request.getWorkFinishTime())
                         .businessDetail(request.getBusinessDetail())
                         .businessType(request.getBusinessType())
                         .salaryType(request.getSalaryType())
                         .salary(request.getSalary())
                         .address(request.getAddress())
                         .latitude(request.getLatitude())
                         .longitude(request.getLongitude())
                         .recruitState("모집중")
                         .build()
         );
         return new BusinessRegisterResponse();
    }

     /*
     * 사업장 목록 조회
     * */
    public List<BusinessListResponse> findAllBusiness() {
        List<Business> businesses = businessRepository.findAll();

        List<BusinessListResponse> response = new ArrayList<>();
        businesses.forEach(business ->
                response.add(new BusinessListResponse(
                        business.getId(),
                        business.getBusinessName(),
                        business.getPhoneNumber(),
                        business.getBusinessType(),
                        business.getRecruitState(),
                        business.getLatitude(),
                        business.getLongitude(),
                        business.getAddress(),
                        ChronoUnit.DAYS.between(LocalDate.parse(business.getWorkStartDate()),
                                LocalDate.parse(business.getWorkFinishDate()))
                )));
        return response;
    }

    /*
    * 사업장 상세 정보 조회
    * */
    public BusinessDetailResponse findBusinessById(Long businessId) {
        Business business = businessRepository.findById(businessId).orElseThrow(EntityNotFoundException::new);
        BusinessDetailResponse response = new BusinessDetailResponse(
                businessId,
                business.getBusinessName(),
                business.getBusinessNumber(),
                business.getPhoneNumber(),
                business.getWorkStartDate(),
                business.getWorkFinishDate(),
                business.getWorkStartTime(),
                business.getWorkFinishTime(),
                business.getBusinessType(),
                business.getSalary(),
                business.getBusinessDetail(),
                business.getAddress(),
                business.getLatitude(),
                business.getLongitude(),
                business.getRecruitState(),
                ChronoUnit.DAYS.between(LocalDate.parse(business.getWorkStartDate()),
                        LocalDate.parse(business.getWorkFinishDate()))
        );
        return response;
    }

    /*
     * 회원별 사업장 목록 조횐
     * */
    public List<MyBusinessListResponse> findBusinessByMemberId(Long memberId) {
        List<Business> businesses = businessRepository.findAll();

        List<MyBusinessListResponse> response = new ArrayList<>();
        businesses.forEach(business ->
                response.add(new MyBusinessListResponse(
                        business.getId(),
                        business.getBusinessName(),
                        business.getBusinessType(),
                        business.getRecruitState(),
                        business.getAddress(),
                        ChronoUnit.DAYS.between(LocalDate.parse(business.getWorkStartDate()),
                                LocalDate.parse(business.getWorkFinishDate()))
                )));
        return response;
    }

    /*
     * 사업장 모집 상태 변경
     * */
    public BusinessUpdateResponse updateBusiness(Long businessId) {
        Business business = businessRepository.findById(businessId).orElseThrow(EntityNotFoundException::new);
        business.setRecruitState("마감");
        businessRepository.save(business);
        return new BusinessUpdateResponse();
    }
}