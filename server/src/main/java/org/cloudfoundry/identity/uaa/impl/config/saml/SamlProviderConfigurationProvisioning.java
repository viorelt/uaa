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

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderProvisioning;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;

import org.springframework.security.saml.key.KeyType;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.config.NetworkConfiguration;
import org.springframework.security.saml.provider.config.RotatingKeys;
import org.springframework.security.saml.provider.identity.config.ExternalServiceProviderConfiguration;
import org.springframework.security.saml.provider.identity.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.config.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;

import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.getHostIfArgIsURL;
import static org.springframework.util.StringUtils.hasText;

public class SamlProviderConfigurationProvisioning {

    private final IdentityProviderProvisioning identityProviderProvisioning;
    private final SamlServiceProviderProvisioning serviceProviderProvisioning;

    public SamlProviderConfigurationProvisioning(
        IdentityProviderProvisioning idpProvisioning,
        SamlServiceProviderProvisioning spProvisioning
        ) {
        this.identityProviderProvisioning = idpProvisioning;
        this.serviceProviderProvisioning = spProvisioning;
    }

    public SamlServerConfiguration getSamlServerConfiguration() {
        return getSamlServerConfiguration(getIdentityZone());
    }

    public SamlServerConfiguration getSamlServerConfiguration(IdentityZone zone) {
        return new SamlServerConfiguration()
            .setNetwork(
                new NetworkConfiguration()
                    .setConnectTimeout(10000)
                    .setReadTimeout(10000)
            )
            .setIdentityProvider(getIdentityProvider(zone))
            .setServiceProvider(getServiceProvider(zone));
    }


    private LocalIdentityProviderConfiguration getIdentityProvider(IdentityZone zone) {
        IdentityZoneConfiguration zconfig = zone.getConfig();
        SamlConfig samlConfig = zconfig.getSamlConfig();
        return getIdentityProvider(samlConfig, zone.getId());

    }

    private LocalServiceProviderConfiguration getServiceProvider(IdentityZone identityZone) {
        IdentityZoneConfiguration zconfig = identityZone.getConfig();
        SamlConfig samlConfig = zconfig.getSamlConfig();
        return getServiceProvider(samlConfig, identityZone.getId());
    }

    private LocalIdentityProviderConfiguration getIdentityProvider(SamlConfig samlConfig, String zoneId) {
        String entityId = getEntityId(samlConfig);
        LocalIdentityProviderConfiguration result = new LocalIdentityProviderConfiguration()
            //.setSignAssertions(samlConfig.isAssertionSigned())
            .setSingleLogoutEnabled(false)
            .setEntityId(entityId)
            .setAlias(getHostIfArgIsURL(entityId))
            .setKeys(getKeys(samlConfig))
            .setPrefix("saml/idp/")
            .setSignMetadata(true);
        List<SamlServiceProvider> activeProviders = serviceProviderProvisioning.retrieveAll(true, zoneId);
        List<ExternalServiceProviderConfiguration> sps =
            (List<ExternalServiceProviderConfiguration>)activeProviders
                .stream()
                .map(
                    p -> getServiceProviderConfiguration(p)
                )
                .collect(Collectors.toList());
        result.setProviders(sps);
        return result;
    }

    private LocalServiceProviderConfiguration getServiceProvider(SamlConfig samlConfig, String zoneId) {
        String entityId = getEntityId(samlConfig);
        LocalServiceProviderConfiguration result = new LocalServiceProviderConfiguration()
            .setSignRequests(samlConfig.isRequestSigned())
            .setWantAssertionsSigned(samlConfig.isWantAssertionSigned())
            .setEntityId(entityId)
            .setAlias(getHostIfArgIsURL(entityId))
            .setKeys(getKeys(samlConfig))
            .setPrefix("saml/")
            .setSignMetadata(true)
            .setSingleLogoutEnabled(true);
        List<IdentityProvider> activeProviders = identityProviderProvisioning.retrieveAll(true, zoneId);
        List<ExternalIdentityProviderConfiguration> idps =
            (List<ExternalIdentityProviderConfiguration>)activeProviders
                .stream()
                .filter(p -> OriginKeys.SAML.equals(p.getType()))
                .map(
                    p -> getIdentityProviderConfiguration(p)
                )
                .collect(Collectors.toList());
        result.setProviders(idps);
        return result;
    }

    private ExternalIdentityProviderConfiguration getIdentityProviderConfiguration(
        IdentityProvider<SamlIdentityProviderDefinition> provider
    ) {
        return new ExternalIdentityProviderConfiguration()
            .setAlias(provider.getOriginKey())
            .setAssertionConsumerServiceIndex(provider.getConfig().getAssertionConsumerIndex())
            .setLinktext(provider.getConfig().getLinkText())
            .setSkipSslValidation(provider.getConfig().isSkipSslValidation())
            .setMetadata(provider.getConfig().getMetaDataLocation());
    }

    private ExternalServiceProviderConfiguration getServiceProviderConfiguration(SamlServiceProvider provider) {
        return new ExternalServiceProviderConfiguration()
            .setAlias(provider.getId())
            //TODO
            //.setSingleSignOnServiceIndex(provider.getConfig().getSingleSignOnServiceIndex())
            .setLinktext(provider.getName())
            .setSkipSslValidation(provider.getConfig().isSkipSslValidation())
            .setMetadata(provider.getConfig().getMetaDataLocation());
    }

    private String getEntityId(SamlConfig samlConfig) {
        if (hasText(samlConfig.getEntityID())) {
            return samlConfig.getEntityID();
        } else {
            String entityId = IdentityZoneHolder.getUaaZone().getConfig().getSamlConfig().getEntityID();
            if (UaaUrlUtils.isUrl(entityId)) {
                return UaaUrlUtils.addSubdomainToUrl(entityId);
            } else {
                return UaaUrlUtils.getSubdomain() + entityId;
            }
        }
    }

    protected RotatingKeys getKeys(SamlConfig samlConfig) {
        //active signing key
        String activeKeyId = samlConfig.getActiveKeyId();
        SamlKey active = samlConfig.getKeys().get(activeKeyId);
        Set<Map.Entry<String, SamlKey>> standbyEntries = samlConfig.getKeys().entrySet();
        if (active == null) {
            if (samlConfig.getKeys().isEmpty()) {
                //inherit from default zone
                SamlConfig defaultConfig = IdentityZoneHolder.getUaaZone().getConfig().getSamlConfig();
                activeKeyId = defaultConfig.getActiveKeyId();
                active = defaultConfig.getKeys().get(activeKeyId);
                standbyEntries = defaultConfig.getKeys().entrySet();
            } else {
                Optional<Map.Entry<String, SamlKey>> first = standbyEntries.stream().findFirst();
                activeKeyId = first.get().getKey();
                active = first.get().getValue();
            }
        }
        //rotating keys minus active
        final String excludeId = activeKeyId;
        List<SimpleKey> standby = standbyEntries.stream()
            .filter(e -> !excludeId.equals(e.getKey()))
            .map(e -> toSimpleKey(e.getKey(), e.getValue()))
            .collect(Collectors.toList());

        RotatingKeys result = new RotatingKeys()
            .setStandBy(standby);
        if (hasText(activeKeyId)) {
            result.setActive(toSimpleKey(activeKeyId, active));
        }
        return result;
    }

    protected SimpleKey toSimpleKey(String id, SamlKey samlKey) {
        return new SimpleKey(
            id,
            samlKey.getKey(),
            samlKey.getCertificate(),
            samlKey.getPassphrase(),
            KeyType.SIGNING
        );
    }

    protected IdentityZone getIdentityZone() {
        return IdentityZoneHolder.get();
    }

}
