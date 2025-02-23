package com.iuh.edu.fit.BEJewelry.Architecture.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.iuh.edu.fit.BEJewelry.Architecture.domain.request.ReqLoginDTO;
import com.iuh.edu.fit.BEJewelry.Architecture.domain.response.ResLoginDTO;
import com.iuh.edu.fit.BEJewelry.Architecture.util.SecurityUtil;

import jakarta.validation.Valid;

@RestController
public class AuthController {
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final SecurityUtil securityUtil;

    public AuthController(AuthenticationManagerBuilder authenticationManagerBuilder, SecurityUtil securityUtil) {
        this.authenticationManagerBuilder = authenticationManagerBuilder;
        this.securityUtil = securityUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<ResLoginDTO> login(@Valid @RequestBody ReqLoginDTO loginDTO) {

        // Nạp input gồm username/password vào Security
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                loginDTO.getUsername(), loginDTO.getPassword());

        // xác thực người dùng => cần viết hàm loadUserByUsername
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // Create a token
        String access_token = this.securityUtil.createToken(authentication);
        ResLoginDTO res = new ResLoginDTO();
        res.setAccessToken(access_token);

        // nạp thông tin (nếu xử lý thành công) vào SecurityContext
        // SecurityContextHolder.getContext().setAuthentication(authentication);

        return ResponseEntity.ok().body(res);
    }
}
