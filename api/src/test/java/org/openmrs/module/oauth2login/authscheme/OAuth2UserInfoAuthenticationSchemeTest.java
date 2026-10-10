/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.oauth2login.authscheme;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.openmrs.User;
import org.openmrs.api.UserService;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.openmrs.api.db.ContextDAO;
import org.openmrs.module.DaemonToken;

import java.util.Arrays;

import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyList;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class OAuth2UserInfoAuthenticationSchemeTest {
	
	@InjectMocks
	private OAuth2UserInfoAuthenticationScheme authScheme;
	
	@Mock
	private ContextDAO contextDAO;
	
	@Mock
	private UserService userService;
	
	@Mock
	private UserInfo userInfo;
	
	@Mock
	private DaemonToken daemonToken;
	
	private OAuth2TokenCredentials credentials;
	
	@Before
	public void setup() {
		Context.setDAO(contextDAO);
		authScheme.setDaemonToken(daemonToken);
		credentials = mock(OAuth2TokenCredentials.class);
		when(credentials.getClientName()).thenReturn("tester");
		when(credentials.getUserInfo()).thenReturn(userInfo);
		when(credentials.getAuthenticationScheme()).thenReturn("oauth2");
		when(daemonToken.getId()).thenReturn("token");
		when(userInfo.getString(UserInfo.PROP_SYSTEMID)).thenReturn("sub-1");
	}
	
	private void assertRefused() {
		try {
			authScheme.authenticate(credentials);
			org.junit.Assert.fail("expected refusal");
		}
		catch (ContextAuthenticationException expected) {
			// refused
		}
	}
	
	@Test
	@SuppressWarnings("unchecked")
	public void authenticate_shouldRefuseAnUnlinkedLocalAccountWithTheSameUsername() throws Exception {
		// KC-58-04: local "tester" keeps its generated system id; a Keycloak "tester" may not take it over
		User local = new User();
		local.setUsername("tester");
		local.setSystemId("3-4");
		when(contextDAO.getUserByUsername("tester")).thenReturn(local);
		assertRefused();
		verify(userInfo, never()).getOpenmrsUser();
		verify(contextDAO, never()).createUser(any(User.class), anyString(), anyList());
	}
	
	@Test
	public void authenticate_shouldRefuseALinkedAccountWhenTheSubjectChanged() throws Exception {
		// KC-58-05: deleted and recreated in Keycloak -> new sub -> refused until re-linked
		User linked = new User();
		linked.setUsername("tester");
		linked.setSystemId("old-sub");
		when(contextDAO.getUserByUsername("tester")).thenReturn(linked);
		assertRefused();
	}
	
	@Test
	public void authenticate_shouldRefuseATokenWithoutASubject() throws Exception {
		when(userInfo.getString(UserInfo.PROP_SYSTEMID)).thenReturn(" ");
		when(contextDAO.getUserByUsername("tester")).thenReturn(null);
		assertRefused();
	}
	
	@Test
	@SuppressWarnings("unchecked")
	public void authenticate_shouldNotCreateASecondAccountForASubjectAlreadyLinked() throws Exception {
		// renamed in Keycloak: new username, same sub already bound to "oldname"
		User bound = new User();
		bound.setUsername("oldname");
		bound.setSystemId("sub-1");
		when(contextDAO.getUserByUsername("tester")).thenReturn(null);
		when(contextDAO.getUserByUsername("sub-1")).thenReturn(bound);
		assertRefused();
		verify(contextDAO, never()).createUser(any(User.class), anyString(), anyList());
	}
	
	@Test
	public void authenticate_shouldCreateNewUserWhenUserDoesNotExist() throws Exception {
		when(contextDAO.getUserByUsername("tester")).thenReturn(null);
		User newUser = new User();
		when(userInfo.getOpenmrsUser(anyString())).thenReturn(newUser);
		when(userInfo.getRoleNames()).thenReturn(Arrays.asList("Provider", "Nurse"));
		
		Authenticated result = authScheme.authenticate(credentials);
		
		verify(contextDAO).createUser(eq(newUser), anyString(), eq(Arrays.asList("Provider", "Nurse")));
		assertNotNull(result);
	}
	
	@Test(expected = ContextAuthenticationException.class)
	public void authenticate_shouldThrowExceptionForInvalidCredentials() {
		Credentials invalidCredentials = mock(Credentials.class);
		
		authScheme.authenticate(invalidCredentials);
	}
	
	@Test
	@SuppressWarnings("unchecked")
	public void authenticate_shouldSkipUserCreationForServiceAccount() throws Exception {
		when(credentials.isServiceAccount()).thenReturn(true);
		User serviceUser = new User();
		serviceUser.setUsername("tester");
		when(contextDAO.getUserByUsername("tester")).thenReturn(serviceUser);
		
		Authenticated result = authScheme.authenticate(credentials);
		
		assertNotNull(result);
		verify(userInfo, never()).getOpenmrsUser(anyString());
		verify(contextDAO, never()).createUser(any(User.class), anyString(), anyList());
	}
	
	@Test
	@SuppressWarnings("unchecked")
	public void authenticate_shouldRefuseALoginNameThatMatchesAnotherAccountsSystemId() throws Exception {
		// getUserByUsername also matches system_id: "tester" here resolves to an account named "admin"
		User other = new User();
		other.setUsername("admin");
		other.setSystemId("tester");
		when(contextDAO.getUserByUsername("tester")).thenReturn(other);
		for (boolean serviceAccount : new boolean[] { false, true }) {
			when(credentials.isServiceAccount()).thenReturn(serviceAccount);
			try {
				authScheme.authenticate(credentials);
				org.junit.Assert.fail("expected refusal, serviceAccount=" + serviceAccount);
			}
			catch (ContextAuthenticationException expected) {
				// refused
			}
		}
		verify(contextDAO, never()).createUser(any(User.class), anyString(), anyList());
		verify(userInfo, never()).getOpenmrsUser(anyString());
	}
	
	@Test
	public void authenticate_shouldRefuseAMatchedAccountWithoutAUsername() throws Exception {
		User noUsername = new User();
		noUsername.setSystemId("tester");
		when(contextDAO.getUserByUsername("tester")).thenReturn(noUsername);
		try {
			authScheme.authenticate(credentials);
			org.junit.Assert.fail("expected refusal");
		}
		catch (ContextAuthenticationException expected) {
			// refused
		}
	}
}
