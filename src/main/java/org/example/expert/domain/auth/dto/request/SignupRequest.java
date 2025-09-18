package org.example.expert.domain.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

public record SignupRequest(
        @NotBlank String email,
        @NotBlank String password,
        @NotBlank String nickname,
        @NotBlank String userRole
) {
}

