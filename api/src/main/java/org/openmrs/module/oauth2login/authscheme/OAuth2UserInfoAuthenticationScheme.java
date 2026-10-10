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

import static org.openmrs.module.oauth2login.OAuth2LoginConstants.AUTH_SCHEME_COMPONENT;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import java.util.Set;

import org.hibernate.Hibernate;
import org.openmrs.Role;
import org.openmrs.User;
import org.openmrs.api.ProviderService;
import org.openmrs.api.UserService;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.BasicAuthenticated;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.openmrs.api.context.Daemon;
import org.openmrs.api.context.DaoAuthenticationScheme;
import org.openmrs.module.DaemonToken;
import org.openmrs.module.DaemonTokenAware;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * A scheme that authenticates with OpenMRS based on the 'username'.
 */
@Transactional
@Component(AUTH_SCHEME_COMPONENT)
public class OAuth2UserInfoAuthenticationScheme extends DaoAuthenticationScheme implements DaemonTokenAware {
	
	protected Log log = LogFactory.getLog(getClass());
	
	private DaemonToken daemonToken;
	
	private AuthenticationPostProcessor postProcessor;
	
	@Autowired
	private UserService userService;
	
	@Autowired
	@Qualifier("providerService")
	private ProviderService ps;
	
	public void setDaemonToken(DaemonToken daemonToken) {
		this.daemonToken = daemonToken;
	}
	
	public void setPostProcessor(AuthenticationPostProcessor postProcessor) {
		this.postProcessor = postProcessor;
	}
	
	public OAuth2UserInfoAuthenticationScheme() {
		setPostProcessor(new AuthenticationPostProcessor() {
			
			@Override
			public void process(UserInfo userInfo) {
				// no post-processing by default
			}
		});
	}
	
	@Override
	public Authenticated authenticate(Credentials credentials) throws ContextAuthenticationException {
		
		OAuth2TokenCredentials creds;
		try {
			creds = (OAuth2TokenCredentials) credentials;
		}
		catch (ClassCastException e) {
			throw new ContextAuthenticationException("The credentials provided did not match those needed for the "
			        + getClass().getSimpleName() + " authentication scheme.", e);
		}
		
		User user = findByUsernameOnly(credentials.getClientName());
		if (!creds.isServiceAccount()) {
			String subject = requireBinding(user, creds.getUserInfo());
			if (user == null) {
				// The subject must not already belong to another account (e.g. renamed in Keycloak).
				if (getContextDAO().getUserByUsername(subject) != null) {
					throw new ContextAuthenticationException("OAuth2 subject is already linked to another account");
				}
				createUser(creds.getUserInfo());
				// Get the user again after the user has been created
				user = findByUsernameOnly(credentials.getClientName());
			} else {
				Set<Role> roles = updateUser(user, creds.getUserInfo());
				// The daemon commits in its own transaction; this one (MariaDB REPEATABLE READ) keeps seeing the
				// old rows, so a re-read still returns the old roles. Hand out the session with the roles the
				// daemon just wrote, detached so nothing is flushed back (KC-58-06: a role granted locally must
				// not survive into the next SSO session).
				if (roles != null) {
					// loaded now: the session reads them after this user is detached
					Hibernate.initialize(user.getUserProperties());
					Hibernate.initialize(user.getPerson());
					Context.evictFromSession(user);
					user.setRoles(roles);
				}
			}
			
			postProcessor.process(creds.getUserInfo());
		}
		return new BasicAuthenticated(user, credentials.getAuthenticationScheme());
	}
	
	/**
	 * ContextDAO#getUserByUsername also matches {@code system_id}, so a login name equal to another
	 * account's system id (e.g. "3-4", or an SSO user's sub) would bind to that account. Accept the
	 * lookup only when the account's username really is the login name.
	 */
	private User findByUsernameOnly(String loginName) {
		User user = getContextDAO().getUserByUsername(loginName);
		if (user != null && (user.getUsername() == null || !user.getUsername().equalsIgnoreCase(loginName))) {
			throw new ContextAuthenticationException("OAuth2 login name matches another account's system id, not a username");
		}
		return user;
	}
	
	/**
	 * An SSO login may only enter an existing account that is linked to it: the account's
	 * {@code system_id} must equal the token's subject (mapped by {@link UserInfo#PROP_SYSTEMID}).
	 * Local accounts keep their generated system ids ("3-4"), so a same-name Keycloak user is
	 * refused until an operator links it (KC-58-04); a user deleted and recreated in Keycloak gets
	 * a new subject and is refused until re-linked (KC-58-05).
	 */
	private String requireBinding(User user, UserInfo userInfo) {
		String subject = userInfo.getString(UserInfo.PROP_SYSTEMID);
		if (StringUtils.isBlank(subject)) {
			throw new ContextAuthenticationException("OAuth2 token has no subject claim (" + UserInfo.PROP_SYSTEMID + ")");
		}
		if (user != null && !subject.equals(user.getSystemId())) {
			throw new ContextAuthenticationException("OAuth2 login is not linked to this OpenMRS account");
		}
		return subject;
	}
	
	private void createUser(UserInfo userInfo) throws ContextAuthenticationException {
		try {
			User user = userInfo.getOpenmrsUser("n/a");
			String password = RandomStringUtils.random(100, true, true);
			getContextDAO().createUser(user, password, userInfo.getRoleNames());
		}
		catch (Exception e) {
			throw new ContextAuthenticationException(e.getMessage(), e);
		}
	}
	
	/**
	 * @return the roles written (eagerly loaded, safe to use detached), or null if the token
	 *         carries none
	 */
	private Set<Role> updateUser(User user, UserInfo userInfo) {
		try {
			UpdateUserTask task = new UpdateUserTask(userService, userInfo);
			// Wait: the roles must be replaced before the authenticated session is handed out.
			Daemon.runInDaemonThreadAndWait(task, daemonToken);
			// the daemon swallows the task's exceptions: a failed update must not hand out a session (fail closed)
			if (task.getFailure() != null) {
				throw new ContextAuthenticationException("OAuth2 user update failed: " + task.getFailure(),
				        task.getFailure());
			}
			return task.getAssignedRoles();
		}
		catch (ContextAuthenticationException e) {
			throw e;
		}
		catch (Exception e) {
			throw new ContextAuthenticationException(e.getMessage(), e);
		}
	}
}
