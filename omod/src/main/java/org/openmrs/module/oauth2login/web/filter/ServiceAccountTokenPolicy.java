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

import java.util.Arrays;
import java.util.Collection;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import io.jsonwebtoken.Claims;

/**
 * Decides whether a signature-verified JWT may log in as a service account.
 * <p>
 * A valid signature only proves the realm issued the token; any client of the realm (or a user's
 * token) carries one. A service-account login is accepted only when the token's issuer is the
 * configured issuer, its authorized party ({@code azp}) is one of the configured machine clients,
 * it is an access token ({@code typ = Bearer}) and it carries the service-account username claim.
 * Fails closed: with the issuer or the client list unset, nothing is accepted.
 */
public final class ServiceAccountTokenPolicy {
	
	/** Expected {@code iss}, e.g. https://host/auth/realms/nidan */
	public static final String PROP_ISSUER = "openmrs.serviceAccount.issuer";
	
	/**
	 * Comma-separated client ids allowed to log in as a service account, e.g.
	 * cis,odoo-sync,portal-sync
	 */
	public static final String PROP_ALLOWED_CLIENTS = "openmrs.serviceAccount.allowedClients";
	
	/**
	 * Optional: when set (e.g. openmrs), the token's {@code aud} must contain it. The realm's
	 * machine clients carry aud=openmrs (backlog KC-01-03); unset keeps sites whose realm predates
	 * that mapper working.
	 */
	public static final String PROP_AUDIENCE = "openmrs.serviceAccount.audience";
	
	private ServiceAccountTokenPolicy() {
	}
	
	/**
	 * @param claims verified token claims
	 * @param props oauth2 properties
	 * @param usernameClaim name of the claim that holds the service-account username
	 * @return null when accepted, otherwise the reason it was refused (for logging)
	 */
	public static String refusal(Claims claims, Properties props, String usernameClaim) {
		String issuer = props.getProperty(PROP_ISSUER);
		Set<String> allowed = Arrays.stream(StringUtils.defaultString(props.getProperty(PROP_ALLOWED_CLIENTS)).split(","))
		        .map(String::trim).filter(StringUtils::isNotEmpty).collect(Collectors.toSet());
		if (StringUtils.isBlank(issuer) || allowed.isEmpty() || StringUtils.isBlank(usernameClaim)) {
			return "service-account login is not configured (" + PROP_ISSUER + ", " + PROP_ALLOWED_CLIENTS
			        + ", username claim)";
		}
		if (!issuer.equals(claims.getIssuer())) {
			return "unexpected issuer";
		}
		if (!"Bearer".equals(claims.get("typ", String.class))) {
			return "not an access token";
		}
		String azp = claims.get("azp", String.class);
		if (azp == null || !allowed.contains(azp)) {
			return "client is not an allowed service account: " + azp;
		}
		String audience = StringUtils.trimToNull(props.getProperty(PROP_AUDIENCE));
		if (audience != null && !hasAudience(claims.get("aud"), audience)) {
			return "token is not for " + audience;
		}
		Object username = claims.get(usernameClaim);
		if (!(username instanceof String) || StringUtils.isBlank((String) username)) {
			return "no service-account username claim";
		}
		return null;
	}
	
	/** {@code aud} is a string or a list of strings (RFC 7519 4.1.3). */
	private static boolean hasAudience(Object aud, String expected) {
		if (aud instanceof String) {
			return expected.equals(aud);
		}
		return aud instanceof Collection && ((Collection<?>) aud).contains(expected);
	}
}
