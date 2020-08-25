package com.liferay.samples.fbo.oauth.validator.configuration;

import com.liferay.portal.configuration.metatype.annotations.ExtendedObjectClassDefinition;
import com.liferay.samples.fbo.oauth.validator.constants.ExternalOAuthConfigurationConstants;

import aQute.bnd.annotation.metatype.Meta;

@ExtendedObjectClassDefinition(
        category = ExternalOAuthConfigurationConstants.CATEGORY_KEY,
        scope = ExtendedObjectClassDefinition.Scope.COMPANY
)
@Meta.OCD(
		id = ExternalOAuthConfigurationConstants.CONFIGURATION_ID,
		localization = "content/Language",
		name = "external-oauth2-configuration"
		)
public interface ExternalOAuthConfiguration {

	@Meta.AD(
			description = "external-oauth2-configuration-url-description",
			id = "external.oauth2.configuration.url",
			name = "external-oauth2-configuration-url",			
			required = false
			)
	public String oauthConfigurationUrl();

	@Meta.AD(
			description = "external-oauth2-scope-claim-description",
			id = "external.oauth2.scope.claim",
			name = "external-oauth2-scope-claim-name",			
			deflt = "scope", 
			required = false
			)
	public String scopeClaim();

	@Meta.AD(
			description = "external-oauth2-screen-name-claim-description",
			id = "external.oauth2.screen.name.claim",
			name = "external-oauth2-screen-name-claim-name",			
			deflt = "username", 
			required = false
			)
	public String screenNameClaim();
	
	@Meta.AD(
			description = "external-oauth2-liferay-client-id-description",
			id = "external.oauth2.liferay.client.id",
			name = "external-oauth2-liferay-client-id-name",			
			required = false
			)
	public String liferayClientIdForExternalOAuthBinding();
	
}
