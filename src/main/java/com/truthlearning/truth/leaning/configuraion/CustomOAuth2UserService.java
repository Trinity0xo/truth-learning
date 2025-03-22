package com.truthlearning.truth.leaning.configuraion;

import com.truthlearning.truth.leaning.domain.User;
import com.truthlearning.truth.leaning.dto.auth.RegisterDto;
import com.truthlearning.truth.leaning.service.UserService;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.util.Collections;

@Component
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserService userService;

    public CustomOAuth2UserService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);
        String email = oauth2User.getAttribute("email");

        User user = this.userService.handleGetUserByEmail(email);
        if(user == null){
            String firstName = oauth2User.getAttribute("given_name");
            String lastName = oauth2User.getAttribute("family_name");

            RegisterDto registerDto = new RegisterDto();
            registerDto.setEmail(email);
            registerDto.setFirstName(firstName);
            registerDto.setLastName(lastName);
            registerDto.setVerified(true);
            registerDto.setPassword(null);

            this.userService.handleCreateNewUser(registerDto);
        }else{
            if(!user.isVerified()){
                this.userService.handleUpdateVerifyStatus(user);
            }
        }

        return new DefaultOAuth2User(
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
                oauth2User.getAttributes(),
                "email"
        );
    }
}
