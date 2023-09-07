package com.groom.domain.business.entity;

import com.groom.domain.member.entity.Member;
import lombok.*;

import javax.persistence.*;

@Entity
@Getter
@Setter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class Business {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id")
    private Member member;
    @Column(nullable = false, unique = true)
    private String businessName;
    @Column(nullable = false, unique = true)
    private String businessNumber;
    @Column(nullable = false)
    private String phoneNumber;
    @Column(nullable = false)
    private String workStartDate;
    @Column(nullable = false)
    private String workFinishDate;
    @Column(nullable = false)
    private String workStartTime;
    @Column(nullable = false)
    private String workFinishTime;
    @Column(nullable = false)
    private String businessType;
    @Column(nullable = false)
    private String salaryType;
    @Column(nullable = false)
    private Integer salary;
    @Column(nullable = false)
    private String businessDetail;
    @Column(nullable = false)
    private String address;
    @Column(nullable = false)
    private Double latitude;
    @Column(nullable = false)
    private Double longitude;
    @Column(nullable = false)
    private String recruitState;
}