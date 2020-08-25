package com.liferay.samples.fbo.oauth.validator;

import java.net.MalformedURLException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

import org.osgi.framework.Bundle;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.liferay.oauth2.provider.scope.ScopeChecker;
import com.liferay.oauth2.provider.scope.liferay.ScopeContext;
import com.liferay.petra.string.StringPool;
import com.liferay.portal.kernel.module.configuration.ConfigurationException;
import com.liferay.portal.kernel.module.configuration.ConfigurationProvider;
import com.liferay.portal.kernel.service.CompanyLocalService;
import com.liferay.portal.kernel.settings.CompanyServiceSettingsLocator;
import com.liferay.samples.fbo.oauth.util.ExternalOAuthUtil;
import com.liferay.samples.fbo.oauth.validator.configuration.ExternalOAuthConfiguration;
import com.liferay.samples.fbo.oauth.validator.constants.ExternalOAuthConfigurationConstants;
import com.liferay.samples.fbo.oauth.validator.model.ExternalOAuthMetadata;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;

@Component(
		immediate=true,
		configurationPid = ExternalOAuthConfigurationConstants.CONFIGURATION_ID,
		configurationPolicy = ConfigurationPolicy.REQUIRE, 
		property = {
				"service.ranking:Integer=100"
			},
		service = {
				ScopeChecker.class,
				ScopeContext.class
				}
		)
public class ExternalScopeChecker implements ScopeChecker, ScopeContext {

	@Override
	public void clear() {

		_accessTokenThreadLocal.remove();
		_applicationNameThreadLocal.remove();
		_bundleSymbolicNameThreadLocal.remove();
		_companyIdThreadLocal.remove();
		
	}

	@Override
	public void setAccessToken(String accessToken) {
		_accessTokenThreadLocal.set(accessToken);
	}

	@Override
	public void setApplicationName(String applicationName) {
		_applicationNameThreadLocal.set(applicationName);
	}

	@Override
	public void setBundle(Bundle bundle) {
		_bundleSymbolicNameThreadLocal.set(bundle.getSymbolicName());
	}

	@Override
	public void setCompanyId(long companyId) {
		_companyIdThreadLocal.set(companyId);
	}

	@Override
	public boolean checkScope(String requestedScope) {

		LOG.debug("Check scope: " + requestedScope);
		LOG.debug("Application name: " + _applicationNameThreadLocal.get());

		try {

			String oauthConfigurationUrl = getConfiguration(_companyIdThreadLocal.get()).oauthConfigurationUrl();
			String scopeClaim = getConfiguration(_companyIdThreadLocal.get()).scopeClaim();
			
			ExternalOAuthMetadata externalOAuthMetadata = ExternalOAuthUtil.getAuthorizationServerMetadata(oauthConfigurationUrl);
			
			String jwksUrl = externalOAuthMetadata.getJwksUrl();
			String issuer = externalOAuthMetadata.getIssuer();
					
			JWTClaimsSet claimsSet = ExternalOAuthUtil.getClaimsSet(_accessTokenThreadLocal.get(), jwksUrl, issuer);
			
			String scopes = claimsSet.getStringClaim(scopeClaim);
			LOG.debug("Token scopes: " + scopes);
			List<String> scopesList = Arrays.asList(scopes.split(" "));
			
			return scopesList.contains(_applicationNameThreadLocal.get());
			
		} catch (MalformedURLException e) {
			LOG.error("Malformed URL exception", e);
		} catch (ParseException e) {
			LOG.error("Parse exception", e);
		} catch (BadJOSEException e) {
			LOG.error("Bad JOSE exception", e);
		} catch (JOSEException e) {
			LOG.error("JOSE exception", e);
		} catch (Exception e) {
			LOG.error("Exception", e);
		}

		return false;
	}
	
	private final ThreadLocal<String> _accessTokenThreadLocal = ThreadLocal.withInitial(() -> StringPool.BLANK);
	private final ThreadLocal<String> _applicationNameThreadLocal = ThreadLocal.withInitial(() -> StringPool.BLANK);
	private final ThreadLocal<String> _bundleSymbolicNameThreadLocal = ThreadLocal.withInitial(() -> StringPool.BLANK);
	private final ThreadLocal<Long> _companyIdThreadLocal = ThreadLocal.withInitial(() -> 0L);
	
	private static final Logger LOG = LoggerFactory.getLogger(ExternalScopeChecker.class);

	private static final String BEARER = "Bearer";
	private static final String ISSUER = "issuer";
	private static final String JWKS_URI = "jwks_uri";
	
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
