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

import org.cloudfoundry.identity.uaa.saml.SamlConfigurationProvider;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.SamlMessageHandler;
import org.springframework.security.saml.config.SamlServerConfiguration;
import org.springframework.security.saml.spi.AbstractProviderConfiguration;
import org.springframework.security.saml.spi.DefaultAuthnRequestHandler;
import org.springframework.security.saml.spi.DefaultSpResponseHandler;

@Configuration
public class HostedSamlConfiguration extends AbstractProviderConfiguration {

    @Bean
    public SamlServerConfiguration samlServerConfiguration() {
        return new SamlConfigurationProvider();
    }

    @Bean
    public SamlMessageHandler discoveryHandler(SamlServerConfiguration configuration) {
        return new DefaultAuthnRequestHandler()
            .setDefaults(defaults())
            .setNetwork(network(configuration))
            .setResolver(resolver())
            .setTransformer(transformer())
            .setConfiguration(configuration);
    }

    @Bean
    public SamlMessageHandler spResponseHandler(SamlServerConfiguration configuration) {
        return new DefaultSpResponseHandler()
            .setDefaults(defaults())
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
}
