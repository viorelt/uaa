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

import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderConfigurator;
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
import org.springframework.security.saml.provider.identity.config.SamlIdentityProviderServerBeanConfiguration;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
public class HostedSamlIdentityProviderConfiguration extends SamlIdentityProviderServerBeanConfiguration {

    private AuthenticationSuccessHandler successHandler;
    private UaaUserDatabase userDatabase;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private SamlServiceProviderProvisioning serviceProviderProvisioning;
    private ScimGroupExternalMembershipManager externalMembershipManager;
    private LogoutSuccessHandler mainLogoutHandler;
    private LogoutHandler uaaAuthenticationFailureHandler;
    private IdentityZoneProvisioning zoneProvisioning;

    public HostedSamlIdentityProviderConfiguration(
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

    @Bean("idpSamlProviderConfigurationProvisioning")
    public SamlProviderConfigurationProvisioning getIdpSamlProviderConfigurationProvisioning() {
        return new SamlProviderConfigurationProvisioning(identityProviderProvisioning, serviceProviderProvisioning);
    }

    @Override
    @Bean(name = "idpSamlConfigurationFilter")
    public Filter samlConfigurationFilter() {
        return new ThreadLocalSamlConfigurationFilter(
            (ThreadLocalSamlConfigurationRepository) samlConfigurationRepository()
        ) {
            @Override
            protected SamlServerConfiguration getConfiguration(HttpServletRequest request) {
                return getIdpSamlProviderConfigurationProvisioning().getSamlServerConfiguration();
            }
        };
    }

    @Bean(name = "spMetaDataProviders")
    public SamlServiceProviderConfigurator samlIdentityProviderConfigurator() {
        SamlServiceProviderConfigurator result = new SamlServiceProviderConfigurator();
        result.setProviderProvisioning(serviceProviderProvisioning);
        result.setResolver(getSamlProvisioning());
        return result;
    }

    @Override
    @DependsOn("identityZoneConfigurationBootstrap")
    protected SamlServerConfiguration getDefaultHostSamlServerConfiguration() {
        IdentityZone zone = zoneProvisioning.retrieve(IdentityZone.getUaa().getId());
        return getIdpSamlProviderConfigurationProvisioning().getSamlServerConfiguration(zone);
    }

    @Override
    @Bean
    public Filter idpMetadataFilter() {
        return super.idpMetadataFilter();
    }

    @Override
    @Bean
    public Filter idpInitatedLoginFilter() {
        return super.idpInitatedLoginFilter();
    }

    @Override
    @Bean
    public Filter idpAuthnRequestFilter() {
        return super.idpAuthnRequestFilter();
    }

    @Override
    @Bean
    public Filter idpLogoutFilter() {
        return super.idpLogoutFilter();
    }

    @Override
    @Bean
    public Filter idpSelectServiceProviderFilter() {
        return super.idpSelectServiceProviderFilter();
    }
}
