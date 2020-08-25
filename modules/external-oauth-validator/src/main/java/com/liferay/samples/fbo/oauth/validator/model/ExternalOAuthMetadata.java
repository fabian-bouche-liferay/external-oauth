package com.liferay.samples.fbo.oauth.validator.model;

public class ExternalOAuthMetadata {

	private String jwksUrl;
	private String issuer;
	
	public String getJwksUrl() {
		return jwksUrl;
	}
	
	public void setJwksUrl(String jwksUrl) {
		this.jwksUrl = jwksUrl;
	}
	
	public String getIssuer() {
		return issuer;
	}
	
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}	
	
}
