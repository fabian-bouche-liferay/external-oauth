package com.liferay.samples.fbo.oauth.validator.configuration;

import org.osgi.service.component.annotations.Component;

import com.liferay.portal.kernel.settings.definition.ConfigurationPidMapping;
import com.liferay.samples.fbo.oauth.validator.constants.ExternalOAuthConfigurationConstants;

@Component
public class ExternalOAuthConfigurationPidMapping implements ConfigurationPidMapping {

	@Override
	public Class<?> getConfigurationBeanClass() {
		return ExternalOAuthConfiguration.class;
	}

	@Override
	public String getConfigurationPid() {
		return ExternalOAuthConfigurationConstants.CONFIGURATION_ID;
	}

}
