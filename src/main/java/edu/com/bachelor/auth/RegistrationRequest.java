package edu.com.bachelor.auth;

import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Builder
public class RegistrationRequest {
    private String login;
    private String password;
    private String email;
}
