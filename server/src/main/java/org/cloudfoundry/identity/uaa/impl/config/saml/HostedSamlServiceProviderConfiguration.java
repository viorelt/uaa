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

import org.cloudfoundry.identity.uaa.authentication.SamlRedirectLogoutHandler;
import org.cloudfoundry.identity.uaa.authentication.UaaSamlLogoutFilter;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSAMLAuthenticationFailureHandler;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationProvider;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.service.authentication.SamlResponseAuthenticationFilter;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.provider.service.config.SamlServiceProviderSecurityConfiguration;
import org.springframework.security.saml.util.Network;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

@Configuration
public class HostedSamlServiceProviderConfiguration extends SamlServiceProviderSecurityConfiguration {

    private AuthenticationSuccessHandler successHandler;
    private UaaUserDatabase userDatabase;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private ScimGroupExternalMembershipManager externalMembershipManager;
    private LogoutSuccessHandler mainLogoutHandler;
    private LogoutHandler uaaAuthenticationFailureHandler;

    public HostedSamlServiceProviderConfiguration(
        @Qualifier("userDatabase") UaaUserDatabase userDb,
        @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning idpProvisioning,
        @Qualifier("externalGroupMembershipManager") ScimGroupExternalMembershipManager extMbrManager,
        @Qualifier("successRedirectHandler") AuthenticationSuccessHandler successHandler,
        @Qualifier("logoutHandler") LogoutSuccessHandler logoutHandler,
        @Qualifier("uaaAuthenticationFailureHandler") LogoutHandler uaaAuthenticationFailureHandler) {
        super(
            new SamlServerConfiguration()
                .setServiceProvider(
                    new LocalServiceProviderConfiguration()
                        .setPrefix("/saml")
                )
        );
        this.userDatabase = userDb;
        this.identityProviderProvisioning = idpProvisioning;
        this.externalMembershipManager = extMbrManager;
        this.successHandler = successHandler;
        this.mainLogoutHandler = logoutHandler;
        this.uaaAuthenticationFailureHandler = uaaAuthenticationFailureHandler;
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
            new Network() //TODO
                .setReadTimeoutMillis(10000)
                .setConnectTimeoutMillis(10000),
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
            new Network()
                .setConnectTimeoutMillis(10000)
                .setReadTimeoutMillis(10000),//TODO
            samlAuthenticationManager()
        );
    }


}
