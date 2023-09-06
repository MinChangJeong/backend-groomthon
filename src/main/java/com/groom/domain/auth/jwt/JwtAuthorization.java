package com.groom.domain.auth.jwt;

import java.lang.annotation.*;

@Target({ ElementType.PARAMETER, ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface JwtAuthorization {

    boolean required() default true;
}