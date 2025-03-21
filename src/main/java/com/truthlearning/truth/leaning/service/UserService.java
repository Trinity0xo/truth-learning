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

        User user = new User();
        user.setEmail(registerDto.getEmail());
        user.setLastName(registerDto.getLastName());
        user.setFirstName(registerDto.getFirstName());
        user.setPassword(registerDto.getPassword());

        return this.userRepository.save(user);
    }

    public void handleUpdateVerifyStatus(User user){
        user.setVerified(true);
    }

    public User handleGetUserByEmail(String email){
        return this.userRepository.findByEmail(email).orElse(null);
    }
}
