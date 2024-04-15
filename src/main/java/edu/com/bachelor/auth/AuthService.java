package edu.com.bachelor.auth;


import edu.com.bachelor.jwt.JwtService;
import edu.com.bachelor.model.Role;
import edu.com.bachelor.model.User;
import edu.com.bachelor.service.user.impls.UserServiceImpl;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;
    private final UserServiceImpl userService;
    public AuthenticationResponse register(RegistrationRequest request){
        User user = User.builder()
                .login(request.getLogin())
                .password(request.getPassword())
                .email(request.getEmail())
                .role(Role.ROLE_USER)
                .build();
        userService.save(user);
        String token = jwtService.generateJwt(user);
        return AuthenticationResponse.builder().token(token).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getLogin(),
                        request.getPassword()
                )
        );
        var user = userDetailsService.loadUserByUsername(request.getLogin());
        String jwt = jwtService.generateJwt(user);
        return AuthenticationResponse.builder().token(jwt).build();
    }
}
