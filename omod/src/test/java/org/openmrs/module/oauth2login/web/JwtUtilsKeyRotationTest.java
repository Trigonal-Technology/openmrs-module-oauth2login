/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.oauth2login.web;

import static io.jsonwebtoken.SignatureAlgorithm.RS256;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

import java.security.PublicKey;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicLong;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import io.jsonwebtoken.Jwts;

/** Backlog KC-58-08: keys rotated out at the identity provider stop being trusted without a restart. */
@RunWith(PowerMockRunner.class)
@PrepareForTest(HttpUtils.class)
public class JwtUtilsKeyRotationTest {

	private static final String URL = "http://keycloak/auth/realms/nidan/protocol/openid-connect/certs";

	private final AtomicLong now = new AtomicLong(1_000_000L);

	private Properties props;

	private RsaJsonWebKey keyA;

	private RsaJsonWebKey keyB;

	@Before
	public void setup() throws Exception {
		mockStatic(HttpUtils.class);
		props = new Properties();
		props.setProperty(JwtUtils.OAUTH_PROP_KEYS_URL, URL);
		props.setProperty(JwtUtils.OAUTH_PROP_KEYS_TTL, "600");
		keyA = RsaJwkGenerator.generateJwk(2048);
		keyA.setKeyId("A");
		keyB = RsaJwkGenerator.generateJwk(2048);
		keyB.setKeyId("B");
		JwtUtils.localPublicKey = null;
		JwtUtils.remoteJsonWebKeySet = null;
		JwtUtils.keysInitialized = false;
		JwtUtils.remoteKeysFetchedAt = 0L;
		JwtUtils.lastForcedRefetchAt = Long.MIN_VALUE / 2;
		JwtUtils.clock = now::get;
	}

	private static String jwks(RsaJsonWebKey... keys) {
		return new JsonWebKeySet(keys).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
	}

	private static String token(RsaJsonWebKey key) {
		return Jwts.builder().setHeaderParam("kid", key.getKeyId()).setSubject("cis").signWith(key.getRsaPrivateKey(), RS256)
		        .compact();
	}

	@Test
	public void aKeyRemovedAtTheProviderIsRefusedAfterTheTtl() throws Exception {
		when(HttpUtils.getJsonWebKeys(URL)).thenReturn(jwks(keyA));
		assertNotNull(JwtUtils.getPublicKey(token(keyA), props));

		// provider rotates: A removed, B published
		when(HttpUtils.getJsonWebKeys(URL)).thenReturn(jwks(keyB));
		now.addAndGet(601_000L);

		assertNull("old key must not verify after the TTL", JwtUtils.getPublicKey(token(keyA), props));
		assertNotNull(JwtUtils.getPublicKey(token(keyB), props));
	}

	@Test
	public void anUnknownKeyIdTriggersOneImmediateRefresh() throws Exception {
		when(HttpUtils.getJsonWebKeys(URL)).thenReturn(jwks(keyA));
		JwtUtils.getPublicKey(token(keyA), props);
		when(HttpUtils.getJsonWebKeys(URL)).thenReturn(jwks(keyA, keyB));
		now.addAndGet(1_000L); // well inside the TTL

		PublicKey key = JwtUtils.getPublicKey(token(keyB), props);

		assertEquals(keyB.getPublicKey(), key);
	}

	@Test
	public void unknownKeyIdRefreshesAreRateLimited() throws Exception {
		when(HttpUtils.getJsonWebKeys(URL)).thenReturn(jwks(keyA));
		JwtUtils.getPublicKey(token(keyA), props);
		now.addAndGet(1_000L);
		assertNull(JwtUtils.getPublicKey(token(keyB), props)); // forced refresh #1: B still unknown
		when(HttpUtils.getJsonWebKeys(URL)).thenReturn(jwks(keyA, keyB));
		now.addAndGet(1_000L);

		assertNull("second forced refresh within 30 s must not happen", JwtUtils.getPublicKey(token(keyB), props));
		PowerMockito.verifyStatic(org.mockito.Mockito.times(2));
		HttpUtils.getJsonWebKeys(anyString());

		now.addAndGet(30_000L);
		assertNotNull(JwtUtils.getPublicKey(token(keyB), props));
	}

	@Test
	public void aFailedRefreshKeepsTheCachedKeys() throws Exception {
		when(HttpUtils.getJsonWebKeys(URL)).thenReturn(jwks(keyA));
		JwtUtils.getPublicKey(token(keyA), props);
		when(HttpUtils.getJsonWebKeys(URL)).thenThrow(new java.io.IOException("keycloak down"));
		now.addAndGet(601_000L);

		assertNotNull("a short identity-provider outage must not stop logins", JwtUtils.getPublicKey(token(keyA), props));
	}
}
