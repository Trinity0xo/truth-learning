package com.truthlearning.truth.leaning.service;

import com.truthlearning.truth.leaning.domain.User;
import com.truthlearning.truth.leaning.dto.auth.RegisterDto;
import com.truthlearning.truth.leaning.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User handleCreateNewUser(RegisterDto registerDto){

//        User user = User.builder()
//                .firstName(registerDto.getFirstName())
//                .lastName(registerDto.getLastName())
//                .email(registerDto.getEmail())
//                .password(registerDto.getPassword())
//                .build();

        return this.userRepository.save(null);
    }

    public User handleGetUserByEmail(String email){
        return this.userRepository.findByEmail(email).orElse(null);
    }
}
