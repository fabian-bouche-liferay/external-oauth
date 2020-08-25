package com.liferay.samples.fbo.oauth.util;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.liferay.samples.fbo.oauth.validator.model.ExternalOAuthMetadata;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

public class ExternalOAuthUtil {
	
	private static final String ISSUER = "issuer";
	private static final String JWKS_URI = "jwks_uri";

	public static JWTClaimsSet getClaimsSet(String accessTokenString, String jwksUrl, String issuer)
			throws MalformedURLException, ParseException, BadJOSEException, JOSEException {

		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

		jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("jwt")));

		JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

		JWKSource<SecurityContext> keySource;
		keySource = new RemoteJWKSet<>(new URL(jwksUrl));

		JWSKeySelector<SecurityContext> keySelector =
		    new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);

		jwtProcessor.setJWSKeySelector(keySelector);

		jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
		    new JWTClaimsSet.Builder().issuer(issuer).build(),
		    new HashSet<>(Arrays.asList("sub", "iat", "exp", "scope", "jti"))));

		SecurityContext ctx = null;
		JWTClaimsSet claimsSet = jwtProcessor.process(accessTokenString, ctx);
		return claimsSet;
	}
	
	public static ExternalOAuthMetadata getAuthorizationServerMetadata(String oauthConfigurationUrl) {
		
		ExternalOAuthMetadata externalOAuthMetadata = new ExternalOAuthMetadata();
		
        CloseableHttpClient httpClient = HttpClients.createDefault();

        try {

        	LOG.debug("OAuth Configuration URL: " + oauthConfigurationUrl);
        	
            HttpGet request = new HttpGet(oauthConfigurationUrl);
            CloseableHttpResponse response = httpClient.execute(request);

            try {

                HttpEntity entity = response.getEntity();
                if (entity != null) {
        			DocumentContext authorizationServerConfiguration = JsonPath.parse(EntityUtils.toString(entity));
        			String jwksUrl = authorizationServerConfiguration.read(JWKS_URI);
        			externalOAuthMetadata.setJwksUrl(jwksUrl);
        			String issuer = authorizationServerConfiguration.read(ISSUER);
        			externalOAuthMetadata.setIssuer(issuer);
                }

            } finally {
                response.close();
            }
        } catch (ClientProtocolException e) {
        	LOG.error("Client protocol exception", e);
		} catch (IOException e) {
        	LOG.error("IO protocol exception", e);
		} finally {
            try {
				httpClient.close();
			} catch (IOException e) {
	        	LOG.error("Client protocol exception", e);
			}
        }
		
		return externalOAuthMetadata;
	}
	
	private static final Logger LOG = LoggerFactory.getLogger(ExternalOAuthUtil.class);

}
