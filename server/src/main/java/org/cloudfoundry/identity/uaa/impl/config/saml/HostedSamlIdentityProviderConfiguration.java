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

import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml.provider.identity.config.SamlIdentityProviderSecurityConfiguration;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
@Order(1)
public class HostedSamlIdentityProviderConfiguration extends SamlIdentityProviderSecurityConfiguration {

    private AuthenticationSuccessHandler successHandler;
    private UaaUserDatabase userDatabase;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private SamlServiceProviderProvisioning serviceProviderProvisioning;
    private ScimGroupExternalMembershipManager externalMembershipManager;
    private LogoutSuccessHandler mainLogoutHandler;
    private LogoutHandler uaaAuthenticationFailureHandler;

    public HostedSamlIdentityProviderConfiguration(
        @Qualifier("userDatabase") UaaUserDatabase userDb,
        @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning idpProvisioning,
        @Qualifier("serviceProviderProvisioning") SamlServiceProviderProvisioning serviceProviderProvisioning,
        @Qualifier("externalGroupMembershipManager") ScimGroupExternalMembershipManager extMbrManager,
        @Qualifier("successRedirectHandler") AuthenticationSuccessHandler successHandler,
        @Qualifier("logoutHandler") LogoutSuccessHandler logoutHandler,
        @Qualifier("uaaAuthenticationFailureHandler") LogoutHandler uaaAuthenticationFailureHandler) {
        super(
            new SamlProviderConfigurationProvisioning(idpProvisioning, serviceProviderProvisioning)
        );
        this.userDatabase = userDb;
        this.identityProviderProvisioning = idpProvisioning;
        this.serviceProviderProvisioning = serviceProviderProvisioning;
        this.externalMembershipManager = extMbrManager;
        this.successHandler = successHandler;
        this.mainLogoutHandler = logoutHandler;
        this.uaaAuthenticationFailureHandler = uaaAuthenticationFailureHandler;
    }

    @Bean(name = "spMetaDataProviders")
    public SamlServiceProviderConfigurator samlIdentityProviderConfigurator() {
        SamlServiceProviderConfigurator result = new SamlServiceProviderConfigurator();
        result.setProviderProvisioning(serviceProviderProvisioning);
        result.setResolver(getSamlProvisioning());
        return result;
    }


}
