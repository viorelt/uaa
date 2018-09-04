/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.impl.config.saml;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

import org.cloudfoundry.identity.uaa.authentication.SamlRedirectLogoutHandler;
import org.cloudfoundry.identity.uaa.authentication.UaaSamlLogoutFilter;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSAMLAuthenticationFailureHandler;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationProvider;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.config.ThreadLocalSamlConfigurationFilter;
import org.springframework.security.saml.provider.config.ThreadLocalSamlConfigurationRepository;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.provider.service.authentication.SamlResponseAuthenticationFilter;
import org.springframework.security.saml.provider.service.config.SamlServiceProviderServerBeanConfiguration;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

@Configuration
public class HostedSamlServiceProviderConfiguration extends SamlServiceProviderServerBeanConfiguration {

    private AuthenticationSuccessHandler successHandler;
    private UaaUserDatabase userDatabase;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private SamlServiceProviderProvisioning serviceProviderProvisioning;
    private ScimGroupExternalMembershipManager externalMembershipManager;
    private LogoutSuccessHandler mainLogoutHandler;
    private LogoutHandler uaaAuthenticationFailureHandler;
    private IdentityZoneProvisioning zoneProvisioning;

    public HostedSamlServiceProviderConfiguration(
        IdentityZoneProvisioning zoneProvisioning,
        @Qualifier("userDatabase") UaaUserDatabase userDb,
        @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning idpProvisioning,
        @Qualifier("serviceProviderProvisioning") SamlServiceProviderProvisioning serviceProviderProvisioning,
        @Qualifier("externalGroupMembershipManager") ScimGroupExternalMembershipManager extMbrManager,
        @Qualifier("successRedirectHandler") AuthenticationSuccessHandler successHandler,
        @Qualifier("logoutHandler") LogoutSuccessHandler logoutHandler,
        @Qualifier("uaaAuthenticationFailureHandler") LogoutHandler uaaAuthenticationFailureHandler) {
        this.userDatabase = userDb;
        this.identityProviderProvisioning = idpProvisioning;
        this.serviceProviderProvisioning = serviceProviderProvisioning;
        this.externalMembershipManager = extMbrManager;
        this.successHandler = successHandler;
        this.mainLogoutHandler = logoutHandler;
        this.uaaAuthenticationFailureHandler = uaaAuthenticationFailureHandler;
        this.zoneProvisioning = zoneProvisioning;
    }

    @Override
    @Bean(name = "samlServiceProviderProvisioning")
    public SamlProviderProvisioning<ServiceProviderService> getSamlProvisioning() {
        return new SamlServiceProviderCustomizer(
            samlConfigurationRepository(),
            samlTransformer(),
            samlValidator(),
            samlMetadataCache()
        );
    }

    @Bean("spSamlProviderConfigurationProvisioning")
    public SamlProviderConfigurationProvisioning getSpSamlProviderConfigurationProvisioning() {
        return new SamlProviderConfigurationProvisioning(identityProviderProvisioning, serviceProviderProvisioning);
    }

    @Override
    @Bean(name = "spSamlConfigurationFilter")
    public Filter samlConfigurationFilter() {
        return new ThreadLocalSamlConfigurationFilter(
            (ThreadLocalSamlConfigurationRepository) samlConfigurationRepository()
        ) {
            @Override
            protected SamlServerConfiguration getConfiguration(HttpServletRequest request) {
                return getSpSamlProviderConfigurationProvisioning().getSamlServerConfiguration();
            }
        };
    }

    @Bean
    @Override
    public Filter spAuthenticationResponseFilter() {
        SamlResponseAuthenticationFilter filter =
            (SamlResponseAuthenticationFilter) super.spAuthenticationResponseFilter();
        filter.setAuthenticationManager(samlAuthenticationManager());
        filter.setAuthenticationFailureHandler(loginSAMLAuthenticationFailureHandler());
        filter.setAuthenticationSuccessHandler(successHandler);
        return filter;
    }

    @Bean(name = "samlLogoutHandler")
    public LogoutHandler logoutHandler() {
        return samlLogoutHandler();
    }

    @Bean(name = "samlAuthenticationProvider")
    public LoginSamlAuthenticationProvider samlAuthenticationManager() {
        LoginSamlAuthenticationProvider result = new LoginSamlAuthenticationProvider();
        result.setUserDatabase(userDatabase);
        result.setIdentityProviderProvisioning(identityProviderProvisioning);
        result.setExternalMembershipManager(externalMembershipManager);

        return result;
    }

    @Bean(name = "idpProviders")
    public SamlIdentityProviderConfigurator idpProviders() {
        return samlIdentityProviderConfigurator();
    }

    @Bean(name = "metaDataProviders")
    public SamlIdentityProviderConfigurator samlIdentityProviderConfigurator() {
        SamlIdentityProviderConfigurator result = new SamlIdentityProviderConfigurator();
        result.setIdentityProviderProvisioning(identityProviderProvisioning);
        result.setResolver(getSamlProvisioning());
        return result;
    }

    @Bean(name = "samlWhitelistLogoutHandler")
    public LogoutSuccessHandler samlWhitelistLogoutHandler() {
        return new SamlRedirectLogoutHandler(mainLogoutHandler);
    }

    @Bean(name = "samlLogoutFilter")
    public Filter samlLogoutFilter() {
        return new UaaSamlLogoutFilter(mainLogoutHandler,
                                       uaaAuthenticationFailureHandler,
                                       samlLogoutHandler(),
                                       getSimpleSpLogoutHandler()
        );
    }

    public SimpleSpLogoutHandler getSimpleSpLogoutHandler() {
        return new SimpleSpLogoutHandler(
            getSamlProvisioning(),
            samlTransformer()
        );
    }

    public SecurityContextLogoutHandler samlLogoutHandler() {
        SecurityContextLogoutHandler handler = new SecurityContextLogoutHandler();
        handler.setInvalidateHttpSession(true);
        return handler;
    }

    @Bean(name = "samlLoginFailureHandler")
    public LoginSAMLAuthenticationFailureHandler loginSAMLAuthenticationFailureHandler() {
        LoginSAMLAuthenticationFailureHandler result = new LoginSAMLAuthenticationFailureHandler();
        result.setDefaultFailureUrl("/saml_error");
        return result;
    }

    @Bean(name = "assertionAuthenticationHandler")
    public SamlAssertionAuthenticationHandler assertionAuthenticationHandler() {
        return new SamlAssertionAuthenticationHandler(
            samlValidator(),
            getSamlProvisioning(),
            samlTransformer(),
            samlAuthenticationManager()
        );
    }

    @Override
    @DependsOn("identityZoneConfigurationBootstrap")
    protected SamlServerConfiguration getDefaultHostSamlServerConfiguration() {
        IdentityZone zone = zoneProvisioning.retrieve(IdentityZone.getUaa().getId());
        return getSpSamlProviderConfigurationProvisioning().getSamlServerConfiguration(zone);
    }

    @Override
    @Bean
    public Filter spMetadataFilter() {
        return super.spMetadataFilter();
    }

    @Override
    @Bean
    public Filter spAuthenticationRequestFilter() {
        return super.spAuthenticationRequestFilter();
    }

    @Override
    @Bean
    public Filter spSamlLogoutFilter() {
        return super.spSamlLogoutFilter();
    }
}
