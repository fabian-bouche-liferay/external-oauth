package com.liferay.samples.fbo.oauth.validator.configuration;

import org.osgi.service.component.annotations.Component;

import com.liferay.configuration.admin.category.ConfigurationCategory;
import com.liferay.samples.fbo.oauth.validator.constants.ExternalOAuthConfigurationConstants;

@Component
public class ExternalOAuthConfigurationCategory implements ConfigurationCategory {

    @Override
    public String getCategoryKey() {
        return ExternalOAuthConfigurationConstants.CATEGORY_KEY;
    }

    @Override
    public String getCategorySection() {
        return ExternalOAuthConfigurationConstants.CATEGORY_SECTION;
    }

    @Override
    public String getCategoryIcon() {
        return ExternalOAuthConfigurationConstants.CATEGORY_ICON;
    }

}