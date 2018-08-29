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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

import org.cloudfoundry.identity.uaa.authentication.ProviderConfigurationException;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationProvider;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.DefaultSamlAuthentication;
import org.springframework.security.saml.util.Network;
import org.springframework.security.saml.validation.ValidationException;

import static org.springframework.http.HttpMethod.GET;

public class SamlAssertionAuthenticationHandler {

    private final SamlValidator validator;
    private final SamlProviderProvisioning<ServiceProviderService> resolver;
    private final SamlTransformer transformer;
    private final Network network;
    private final LoginSamlAuthenticationProvider authenticationProvider;

    public SamlAssertionAuthenticationHandler(SamlValidator validator,
                                              SamlProviderProvisioning<ServiceProviderService> resolver,
                                              SamlTransformer transformer,
                                              Network network,
                                              LoginSamlAuthenticationProvider authenticationProvider) {
        this.validator = validator;
        this.resolver = resolver;
        this.transformer = transformer;
        this.network = network;
        this.authenticationProvider = authenticationProvider;
    }

    public Authentication authenticate(HttpServletRequest request,
                                       HttpServletResponse response,
                                       String assertionParamValue) throws AuthenticationException {

//        LocalServiceProviderConfiguration serviceProvider = getConfiguration().getServiceProvider();
        ServiceProviderMetadata metadata = getResolver().getHostedProvider().getMetadata();
        List<SimpleKey> keys = metadata.getServiceProvider().getKeys();
        String xml = getTransformer().samlDecode(assertionParamValue, GET.matches(request.getMethod()));
        Assertion assertion = (Assertion) getTransformer().fromXml(xml, null, keys);
        IdentityProviderMetadata idpMetadata = getResolver().getHostedProvider().getRemoteProvider(assertion);
        //validates the signature
        assertion = (Assertion) getTransformer().fromXml(xml, keys, idpMetadata.getIdentityProvider().getKeys());
        ValidationException validation = validateAssertion(request, assertion);
        if (validation == null) {
            DefaultSamlAuthentication authentication = new DefaultSamlAuthentication(
                false,
                assertion,
                idpMetadata.getEntityId(),
                metadata.getEntityId(),
                request.getParameter("RelayState")
            );
            return authenticationProvider.authenticate(authentication);
        } else {
            throw new ProviderConfigurationException("Unable to validate assertion.", validation);
        }
    }


    protected ValidationException validateAssertion(HttpServletRequest request, Assertion assertion) {
        return null;
    }

    public SamlValidator getValidator() {
        return validator;
    }

    public SamlProviderProvisioning<ServiceProviderService> getResolver() {
        return resolver;
    }


    public SamlTransformer getTransformer() {
        return transformer;
    }
}
