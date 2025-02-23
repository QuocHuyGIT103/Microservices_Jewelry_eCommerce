package com.iuh.edu.fit.BEJewelry.Architecture.domain.response;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ResLoginDTO {
    @JsonProperty("access_token")
    private String accessToken;

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }
}
