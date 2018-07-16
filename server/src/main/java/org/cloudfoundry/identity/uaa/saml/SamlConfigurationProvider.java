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

package org.cloudfoundry.identity.uaa.saml;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;

import org.springframework.security.saml.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.config.RotatingKeys;
import org.springframework.security.saml.config.SamlServerConfiguration;
import org.springframework.security.saml.key.KeyType;
import org.springframework.security.saml.key.SimpleKey;

import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.getHostIfArgIsURL;
import static org.springframework.util.StringUtils.hasText;

public class SamlConfigurationProvider extends SamlServerConfiguration {

    @Override
    public LocalIdentityProviderConfiguration getIdentityProvider() {
        IdentityZoneConfiguration zconfig = getIdentityZone().getConfig();
        SamlConfig samlConfig = zconfig.getSamlConfig();
        return getIdentityProvider(samlConfig);

    }

    @Override
    public LocalServiceProviderConfiguration getServiceProvider() {
        IdentityZoneConfiguration zconfig = getIdentityZone().getConfig();
        SamlConfig samlConfig = zconfig.getSamlConfig();
        return getServiceProvider(samlConfig);
    }

    protected LocalIdentityProviderConfiguration getIdentityProvider(SamlConfig samlConfig) {
        String entityId = getEntityId(samlConfig);
        return new LocalIdentityProviderConfiguration()
            //.setSignAssertions(samlConfig.isAssertionSigned())
            .setSingleLogoutEnabled(false)
            .setEntityId(entityId)
            .setAlias(getHostIfArgIsURL(entityId))
            .setKeys(getKeys(samlConfig))
            .setPrefix("saml/idp/")
            .setSignMetadata(true)
            ;
    }

    protected LocalServiceProviderConfiguration getServiceProvider(SamlConfig samlConfig) {
        String entityId = getEntityId(samlConfig);
        LocalServiceProviderConfiguration result = new LocalServiceProviderConfiguration()
            .setSignRequests(samlConfig.isRequestSigned())
            .setWantAssertionsSigned(samlConfig.isWantAssertionSigned())
            .setEntityId(entityId)
            .setAlias(getHostIfArgIsURL(entityId))
            .setKeys(getKeys(samlConfig))
            .setPrefix("saml/")
            .setSignMetadata(true)
            .setSingleLogoutEnabled(true)
            ;
        return result;
    }

    protected String getEntityId(SamlConfig samlConfig) {
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
        if (active==null) {
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

        return new RotatingKeys()
            .setActive(toSimpleKey(activeKeyId, active))
            .setStandBy(standby);
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
