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

import java.util.Arrays;
import java.util.List;

import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationProvider;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.saml.SamlConfigurationProvider;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.saml.SamlMessageHandler;
import org.springframework.security.saml.config.SamlServerConfiguration;
import org.springframework.security.saml.spi.AbstractProviderConfiguration;
import org.springframework.security.saml.spi.DefaultSpResponseHandler;

@Configuration
public class HostedSamlConfiguration extends AbstractProviderConfiguration {

    private UaaUserDatabase userDatabase;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private ScimGroupExternalMembershipManager externalMembershipManager;

    public HostedSamlConfiguration(
        @Qualifier("userDatabase") UaaUserDatabase userDb,
        @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning idpProvisioning,
        @Qualifier("externalGroupMembershipManager") ScimGroupExternalMembershipManager extMbrManager) {

        this.userDatabase = userDb;
        this.identityProviderProvisioning = idpProvisioning;
        this.externalMembershipManager = extMbrManager;
    }

    @Bean
    public SamlServerConfiguration samlServerConfiguration() {
        return new SamlConfigurationProvider(identityProviderProvisioning);
    }

    @Bean
    public SamlMessageHandler discoveryHandler(SamlServerConfiguration configuration) {
        return new SamlDiscoveryHandler()
            .setSamlDefaults(samlDefaults())
            .setNetwork(network(configuration))
            .setResolver(resolver())
            .setTransformer(transformer())
            .setConfiguration(configuration);
    }

    @Bean
    public SamlMessageHandler spResponseHandler(SamlServerConfiguration configuration) {
        return new DefaultSpResponseHandler()
            .setAuthenticationManager(samlAuthenticationManager())
            .setSamlDefaults(samlDefaults())
            .setNetwork(network(configuration))
            .setResolver(resolver())
            .setTransformer(transformer())
            .setConfiguration(configuration)
            .setValidator(validator());
    }

    @Override
    @Bean(name = "samlLogoutHandler")
    public SamlMessageHandler logoutHandler(SamlServerConfiguration configuration) {
        return super.logoutHandler(configuration);
    }

    @Override
    @Bean
    public List<SamlMessageHandler> handlers(SamlServerConfiguration configuration) {
        return Arrays.asList(
            metadataHandler(configuration),
            discoveryHandler(configuration),
            logoutHandler(configuration),
            spResponseHandler(configuration)
        );
    }

    @Bean(name = "samlAuthenticationProvider")
    public AuthenticationManager samlAuthenticationManager() {
        LoginSamlAuthenticationProvider result = new LoginSamlAuthenticationProvider();
        result.setUserDatabase(userDatabase);
        result.setIdentityProviderProvisioning(identityProviderProvisioning);
        result.setExternalMembershipManager(externalMembershipManager);
        result.setResolver(resolver());
        return result;
    }

//    <bean id="idpProviders" class="org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator">
//        <property name="identityProviderProvisioning" ref="identityProviderProvisioning"/>
//    </bean>
    @Bean(name = "idpProviders")
    public SamlIdentityProviderConfigurator idpProviders() {
        return samlIdentityProviderConfigurator();
    }

    @Bean(name = "metaDataProviders")
    public SamlIdentityProviderConfigurator samlIdentityProviderConfigurator() {
        SamlIdentityProviderConfigurator result = new SamlIdentityProviderConfigurator();
        result.setIdentityProviderProvisioning(identityProviderProvisioning);
        result.setResolver(resolver());
        return result;
    }

}
