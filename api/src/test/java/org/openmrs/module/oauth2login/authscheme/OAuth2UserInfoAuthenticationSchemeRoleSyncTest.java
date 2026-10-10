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

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.verifyStatic;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.openmrs.Role;
import org.openmrs.User;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.Daemon;
import org.openmrs.api.db.ContextDAO;
import org.openmrs.module.DaemonToken;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;

/**
 * Backlog KC-58-06: roles are replaced BEFORE the session is handed out, so an account that held a
 * superuser role locally does not keep it for its first SSO session.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(Daemon.class)
public class OAuth2UserInfoAuthenticationSchemeRoleSyncTest {
	
	@Test
	public void authenticate_shouldHandOutTheRolesTheUpdateWrote() throws Exception {
		mockStatic(Daemon.class);
		ContextDAO dao = mock(ContextDAO.class);
		Context.setDAO(dao);
		OAuth2UserInfoAuthenticationScheme scheme = new OAuth2UserInfoAuthenticationScheme();
		Whitebox.setInternalState(scheme, "daemonToken", mock(DaemonToken.class));
		
		OAuth2TokenCredentials creds = mock(OAuth2TokenCredentials.class);
		when(creds.getClientName()).thenReturn("nurse1");
		UserInfo info = mock(UserInfo.class);
		when(info.getString(UserInfo.PROP_SYSTEMID)).thenReturn("sub-n1");
		when(creds.getUserInfo()).thenReturn(info);
		when(creds.getAuthenticationScheme()).thenReturn("oauth2");
		// what this request's transaction sees: the account with a locally granted role
		User stale = new User();
		stale.setUsername("nurse1");
		stale.setSystemId("sub-n1");
		stale.setRoles(new HashSet<>(Collections.singleton(new Role("System Developer"))));
		when(dao.getUserByUsername("nurse1")).thenReturn(stale);
		Set<Role> fromToken = new HashSet<>(Collections.singleton(new Role("Organizational: Nurse")));
		doAnswer(inv -> {
			Whitebox.setInternalState(inv.getArguments()[0], "assignedRoles", fromToken);
			return null;
		}).when(Daemon.class);
		Daemon.runInDaemonThreadAndWait(any(Runnable.class), any(DaemonToken.class));
		
		Authenticated result = scheme.authenticate(creds);
		
		verifyStatic(times(1));
		Daemon.runInDaemonThreadAndWait(any(Runnable.class), any(DaemonToken.class));
		verifyStatic(times(0));
		Daemon.runInDaemonThread(any(Runnable.class), any(DaemonToken.class));
		verify(dao).evictFromSession(stale);
		assertEquals("the session must carry the roles just written, not the stale ones", fromToken,
		    result.getUser().getRoles());
	}
	
	@Test(expected = org.openmrs.api.context.ContextAuthenticationException.class)
	public void authenticate_shouldRefuseTheLoginWhenTheUpdateFailed() throws Exception {
		mockStatic(Daemon.class);
		ContextDAO dao = mock(ContextDAO.class);
		Context.setDAO(dao);
		OAuth2UserInfoAuthenticationScheme scheme = new OAuth2UserInfoAuthenticationScheme();
		Whitebox.setInternalState(scheme, "daemonToken", mock(DaemonToken.class));
		OAuth2TokenCredentials creds = mock(OAuth2TokenCredentials.class);
		when(creds.getClientName()).thenReturn("nurse1");
		UserInfo info = mock(UserInfo.class);
		when(info.getString(UserInfo.PROP_SYSTEMID)).thenReturn("sub-n1");
		when(creds.getUserInfo()).thenReturn(info);
		User user = new User();
		user.setUsername("nurse1");
		user.setSystemId("sub-n1");
		when(dao.getUserByUsername("nurse1")).thenReturn(user);
		// the daemon swallows exceptions: the task records the failure instead
		doAnswer(inv -> {
			Whitebox.setInternalState(inv.getArguments()[0], "failure", new RuntimeException("db down"));
			return null;
		}).when(Daemon.class);
		Daemon.runInDaemonThreadAndWait(any(Runnable.class), any(DaemonToken.class));
		
		scheme.authenticate(creds);
	}
}
