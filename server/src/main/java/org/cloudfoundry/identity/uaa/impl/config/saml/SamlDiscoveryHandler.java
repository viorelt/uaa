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
import java.util.Optional;

import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.saml.config.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.spi.DefaultAuthnRequestHandler;

public class SamlDiscoveryHandler extends DefaultAuthnRequestHandler {


    @Override
    protected IdentityProviderMetadata getIdentityProvider(HttpServletRequest request) {
        ExternalIdentityProviderConfiguration idp = getSamlIdp(request);
        return getResolver().resolveIdentityProvider(idp);
    }


    @SuppressWarnings("checked")
    protected ExternalIdentityProviderConfiguration getSamlIdp(HttpServletRequest request) {
        String idp = request.getParameter("idp");
        LocalServiceProviderConfiguration config = getConfiguration().getServiceProvider();
        Optional<ExternalIdentityProviderConfiguration> result =
            config.getProviders().stream()
                .filter(
                    p -> idp.equals(p.getAlias())
                )
                .findFirst();
        if (result.isPresent()) {
            return result.get();
        } else {
            throw new ProviderNotFoundException(idp);
        }
    }


}
