package com.liferay.samples.fbo.oauth.validator.configuration;

import org.osgi.service.component.annotations.Component;

import com.liferay.portal.kernel.settings.definition.ConfigurationBeanDeclaration;

@Component
public class ExternalOAuthConfigurationBeanDeclaration implements ConfigurationBeanDeclaration {

	@Override
	public Class<?> getConfigurationBeanClass() {
		return ExternalOAuthConfiguration.class;
	}
	
}
