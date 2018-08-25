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

import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.SamlAuthenticationRequestByIdpAliasFilter;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class SamlDiscoveryHandler extends SamlAuthenticationRequestByIdpAliasFilter {

    public SamlDiscoveryHandler(SamlProviderProvisioning<ServiceProviderService> provisioning) {
        super(provisioning);
    }

    public SamlDiscoveryHandler(SamlProviderProvisioning<ServiceProviderService> provisioning, RequestMatcher requestMatcher) {
        super(provisioning, requestMatcher);
    }
}
