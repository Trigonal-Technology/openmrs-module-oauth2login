/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.oauth2login.web.filter;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.junit.Test;

import io.jsonwebtoken.impl.DefaultClaims;

/** Backlog KC-58-01: which verified tokens may log in as a service account. */
public class ServiceAccountTokenPolicyTest {
	
	private static final String ISS = "https://ehr.example/auth/realms/nidan";
	
	private static Properties props() {
		Properties p = new Properties();
		p.setProperty(ServiceAccountTokenPolicy.PROP_ISSUER, ISS);
		p.setProperty(ServiceAccountTokenPolicy.PROP_ALLOWED_CLIENTS, "cis, odoo-sync,portal-sync");
		return p;
	}
	
	private static DefaultClaims claims(String iss, String typ, String azp, String user) {
		Map<String, Object> m = new HashMap<>();
		m.put("iss", iss);
		m.put("typ", typ);
		m.put("azp", azp);
		if (user != null) {
			m.put("openmrs_user", user);
		}
		return new DefaultClaims(m);
	}
	
	@Test
	public void acceptsAMachineClientAccessToken() {
		for (String client : new String[] { "cis", "odoo-sync", "portal-sync" }) {
			assertNull(client,
			    ServiceAccountTokenPolicy.refusal(claims(ISS, "Bearer", client, "nidan-sync"), props(), "openmrs_user"));
		}
	}
	
	@Test
	public void refusesTokensFromOtherClientsEvenWhenSignedByTheRealm() {
		for (String client : new String[] { "nidan-gateway", "openmrs", "superset", "", null }) {
			assertNotNull(String.valueOf(client),
			    ServiceAccountTokenPolicy.refusal(claims(ISS, "Bearer", client, "nidan-sync"), props(), "openmrs_user"));
		}
	}
	
	@Test
	public void refusesWrongIssuerIdTokensAndMissingUsername() {
		assertNotNull(ServiceAccountTokenPolicy.refusal(
		    claims("https://evil/auth/realms/nidan", "Bearer", "cis", "nidan-sync"), props(), "openmrs_user"));
		assertNotNull(ServiceAccountTokenPolicy.refusal(claims(ISS, "ID", "cis", "nidan-sync"), props(), "openmrs_user"));
		assertNotNull(ServiceAccountTokenPolicy.refusal(claims(ISS, null, "cis", "nidan-sync"), props(), "openmrs_user"));
		assertNotNull(ServiceAccountTokenPolicy.refusal(claims(ISS, "Bearer", "cis", null), props(), "openmrs_user"));
		assertNotNull(ServiceAccountTokenPolicy.refusal(claims(ISS, "Bearer", "cis", " "), props(), "openmrs_user"));
	}
	
	@Test
	public void failsClosedWhenNotConfigured() {
		DefaultClaims good = claims(ISS, "Bearer", "cis", "nidan-sync");
		assertNotNull(ServiceAccountTokenPolicy.refusal(good, new Properties(), "openmrs_user"));
		Properties noClients = props();
		noClients.setProperty(ServiceAccountTokenPolicy.PROP_ALLOWED_CLIENTS, " , ");
		assertNotNull(ServiceAccountTokenPolicy.refusal(good, noClients, "openmrs_user"));
		assertNotNull(ServiceAccountTokenPolicy.refusal(good, props(), null));
	}
	
	private static DefaultClaims withAudience(Object aud) {
		DefaultClaims c = claims(ISS, "Bearer", "cis", "nidan-sync");
		if (aud != null) {
			c.put("aud", aud);
		}
		return c;
	}
	
	@Test
	public void requiresTheAudienceWhenConfigured() {
		Properties p = props();
		p.setProperty(ServiceAccountTokenPolicy.PROP_AUDIENCE, "openmrs");
		assertNull(ServiceAccountTokenPolicy.refusal(withAudience("openmrs"), p, "openmrs_user"));
		assertNull(ServiceAccountTokenPolicy.refusal(withAudience(Arrays.asList("odoo", "openmrs")), p, "openmrs_user"));
		assertNotNull(ServiceAccountTokenPolicy.refusal(withAudience(null), p, "openmrs_user"));
		assertNotNull(ServiceAccountTokenPolicy.refusal(withAudience("odoo"), p, "openmrs_user"));
		assertNotNull(ServiceAccountTokenPolicy.refusal(withAudience(Arrays.asList("odoo", "openmrs-x")), p, "openmrs_user"));
	}
	
	@Test
	public void audienceIsNotRequiredUntilConfigured() {
		assertNull(ServiceAccountTokenPolicy.refusal(withAudience(null), props(), "openmrs_user"));
	}
}
