package com.liferay.samples.fbo.oauth.validator;

import java.net.MalformedURLException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.client.methods.HttpGet;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.liferay.oauth2.provider.model.OAuth2Application;
import com.liferay.oauth2.provider.rest.spi.bearer.token.provider.BearerTokenProvider;
import com.liferay.oauth2.provider.scope.liferay.ScopeContext;
import com.liferay.oauth2.provider.service.OAuth2ApplicationLocalService;
import com.liferay.oauth2.provider.service.OAuth2ApplicationScopeAliasesLocalService;
import com.liferay.oauth2.provider.service.OAuth2AuthorizationLocalService;
import com.liferay.petra.string.StringPool;
import com.liferay.portal.kernel.exception.PortalException;
import com.liferay.portal.kernel.module.configuration.ConfigurationException;
import com.liferay.portal.kernel.module.configuration.ConfigurationProvider;
import com.liferay.portal.kernel.security.auth.AccessControlContext;
import com.liferay.portal.kernel.security.auth.AuthException;
import com.liferay.portal.kernel.security.auth.verifier.AuthVerifier;
import com.liferay.portal.kernel.security.auth.verifier.AuthVerifierResult;
import com.liferay.portal.kernel.service.CompanyLocalService;
import com.liferay.portal.kernel.service.UserLocalService;
import com.liferay.portal.kernel.settings.CompanyServiceSettingsLocator;
import com.liferay.portal.kernel.util.Portal;
import com.liferay.samples.fbo.oauth.util.ExternalOAuthUtil;
import com.liferay.samples.fbo.oauth.validator.configuration.ExternalOAuthConfiguration;
import com.liferay.samples.fbo.oauth.validator.constants.ExternalOAuthConfigurationConstants;
import com.liferay.samples.fbo.oauth.validator.model.ExternalOAuthMetadata;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;

@Component(
		immediate = true,
		configurationPid = ExternalOAuthConfigurationConstants.CONFIGURATION_ID,
		configurationPolicy = ConfigurationPolicy.REQUIRE, 
		property = {
				"auth.verifier.ExternalOAuthValidator.urls.includes=#N/A#"
		},
		service = AuthVerifier.class
	)
public class ExternalOAuthValidator implements AuthVerifier {

	private static final String AUTHORIZATION = "Authorization";
	private static final String BEARER = "Bearer";
	private static final String OAUTH2 = "OAuth2";

	@Override
	public String getAuthType() {
		return OAUTH2;
	}
	
	@Override
	public AuthVerifierResult verify(AccessControlContext accessControlContext, Properties properties)
			throws AuthException {

		LOG.debug("Verifying ExternalOAuth");
		
		AuthVerifierResult authVerifierResult = new AuthVerifierResult();

		HttpServletRequest httpServletRequest =
			accessControlContext.getRequest();

		String authorizationHeader = httpServletRequest.getHeader(AUTHORIZATION);
		
		if (authorizationHeader == null) {
			return authVerifierResult;
		}
		
		if (!authorizationHeader.startsWith(BEARER)) {
			return authVerifierResult;
		}
		
		String accessTokenString = authorizationHeader.substring(7).trim();

		LOG.debug("Access Token: " + accessTokenString);
		
		return verifyExternalAccessToken(authVerifierResult, httpServletRequest, accessTokenString);
	}

	private AuthVerifierResult verifyExternalAccessToken(AuthVerifierResult authVerifierResult,
			HttpServletRequest httpServletRequest, String accessTokenString) {
		
		try {
			
			long companyId = _portal.getCompanyId(httpServletRequest);

			String oauthConfigurationUrl = getConfiguration(companyId).oauthConfigurationUrl();

			ExternalOAuthMetadata externalOAuthMetadata = ExternalOAuthUtil.getAuthorizationServerMetadata(oauthConfigurationUrl);
			
			String jwksUrl = externalOAuthMetadata.getJwksUrl();
			String issuer = externalOAuthMetadata.getIssuer();

			String screenNameClaim = getConfiguration(companyId).screenNameClaim();

			JWTClaimsSet claimsSet = ExternalOAuthUtil.getClaimsSet(accessTokenString, jwksUrl, issuer);

			LOG.debug("Claim set: " + claimsSet.toJSONObject().toJSONString());

			String screenName = claimsSet.getStringClaim(screenNameClaim);

			long userId = _userLocalService.getUserByScreenName(companyId, screenName).getUserId();
			
			OAuth2Application oAuth2Application = _oAuth2ApplicationLocalService.getOAuth2Application(companyId, getConfiguration(companyId).liferayClientIdForExternalOAuthBinding());
			long expiresIn = claimsSet.getExpirationTime().getTime();
			long issuedAt = claimsSet.getIssueTime().getTime();
			String scopes = claimsSet.getStringClaim(getConfiguration(companyId).scopeClaim());
			List<String> scopeAliasesList = Arrays.asList(scopes.split(" "));
			String accessTokenContent = accessTokenString;
			
			BearerTokenProvider.AccessToken accessToken = new BearerTokenProvider.AccessToken(
					oAuth2Application,
					new ArrayList<>(),
					StringPool.BLANK,
					expiresIn,
					new HashMap<>(),
					StringPool.BLANK,
					StringPool.BLANK,
					issuedAt,
					StringPool.BLANK,
					StringPool.BLANK,
					new HashMap<>(),
					StringPool.BLANK,
					StringPool.BLANK,
					scopeAliasesList,
					accessTokenContent,
					BEARER,
					userId,
					screenName);
			
			Map<String, Object> settings = authVerifierResult.getSettings();

			settings.put(BearerTokenProvider.AccessToken.class.getName(), accessToken);

			authVerifierResult.setState(AuthVerifierResult.State.SUCCESS);
			authVerifierResult.setUserId(accessToken.getUserId());
			
			// Put access token in thread local to allow ScopeChecker to validate scopes
			_scopeContext.setAccessToken(accessTokenString);
			
		} catch (MalformedURLException e) {
			LOG.error("Malformed JWKS URL", e);
			return authVerifierResult;
		} catch (ParseException e) {
			LOG.error("JWT Parsing exception", e);
			return authVerifierResult;
		} catch (BadJOSEException e) {
			LOG.error("Bad JOSE Exception", e);
			return authVerifierResult;
		} catch (JOSEException e) {
			LOG.error("JOSE Exception", e);
			return authVerifierResult;
		} catch (PortalException e) {
			LOG.error("Portal Exception", e);
			return authVerifierResult;
		} catch (Exception e) {
			LOG.error("Exception", e);
			return authVerifierResult;
		}

		LOG.info("Successful verification of access token");

		return authVerifierResult;
	}
	
	private static final Logger LOG = LoggerFactory.getLogger(ExternalOAuthValidator.class);

	@Reference
	private Portal _portal;
	
	@Reference
	private UserLocalService _userLocalService;

	@Reference
	private OAuth2ApplicationLocalService _oAuth2ApplicationLocalService;

	@Reference
	private OAuth2ApplicationScopeAliasesLocalService
		_oAuth2ApplicationScopeAliasesLocalService;

	@Reference
	private OAuth2AuthorizationLocalService _oAuth2AuthorizationLocalService;

    @Reference  (
            unbind = "-",
            target = "(component.name=com.liferay.samples.fbo.oauth.validator.ExternalScopeChecker)"
        )
    private ScopeContext _scopeContext;
    
	/**
	 * Returns the plugin's configuration based on the company ID.
	 *
	 * @param  companyId the ID of the portal instance to which the user belongs
	 * @return {@link ExternalOAuthConfiguration}
	 */
	private ExternalOAuthConfiguration getConfiguration(long companyId) {
		try {
			return configurationProvider.getConfiguration(
					ExternalOAuthConfiguration.class,
					new CompanyServiceSettingsLocator(companyId, ExternalOAuthConfigurationConstants.CONFIGURATION_ID));
		}
		catch (ConfigurationException ce) {
			LOG.error("Error initializing the configuration", ce);
		}

		return null;
	}
	
	@Reference
	private ConfigurationProvider configurationProvider;

	@Reference
	private CompanyLocalService companyLocalService;
	
}
