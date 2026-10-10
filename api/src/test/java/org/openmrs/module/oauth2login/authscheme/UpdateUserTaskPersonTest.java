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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.openmrs.Person;
import org.openmrs.PersonAddress;
import org.openmrs.PersonName;
import org.openmrs.User;
import org.openmrs.api.UserService;

/**
 * Found on the real-OpenMRS harness (KC-36-01): an existing account linked to Keycloak kept its old
 * name, because the person is skipped by the generic copy (OpenMRS objects are equal by uuid).
 */
public class UpdateUserTaskPersonTest {
	
	@Test
	public void run_shouldUpdateTheNameAndGenderOfAnExistingAccountAndKeepTheRest() {
		Person person = new Person();
		person.setGender("M");
		person.addName(new PersonName("Old", null, "Name"));
		PersonAddress address = new PersonAddress();
		address.setCityVillage("Charikot");
		person.addAddress(address);
		User existing = new User(person);
		existing.setUsername("linked1");
		
		Person fromToken = new Person();
		fromToken.setGender("F");
		User mapped = new User(fromToken);
		mapped.setUsername("linked1");
		mapped.addName(new PersonName("Sita", null, "Rai"));
		
		UserInfo info = mock(UserInfo.class);
		when(info.getUsername()).thenReturn("linked1");
		when(info.getOpenmrsUser()).thenReturn(mapped);
		UserService us = mock(UserService.class);
		when(us.getUserByUsername("linked1")).thenReturn(existing);
		
		new UpdateUserTask(us, info).run();
		
		ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
		verify(us).saveUser(saved.capture());
		Person p = saved.getValue().getPerson();
		assertEquals("Sita", p.getPersonName().getGivenName());
		assertEquals("Rai", p.getPersonName().getFamilyName());
		assertEquals(1, p.getNames().size());
		assertEquals("F", p.getGender());
		assertEquals("Charikot", p.getPersonAddress().getCityVillage());
	}
	
	@Test
	public void run_shouldKeepTheFailureAndHandOutNoRolesWhenTheSaveFails() {
		Person person = new Person();
		person.addName(new PersonName("Old", null, "Name"));
		User existing = new User(person);
		existing.setUsername("nurse1");
		User mapped = new User(new Person());
		mapped.setUsername("nurse1");
		UserInfo info = mock(UserInfo.class);
		when(info.getUsername()).thenReturn("nurse1");
		when(info.getOpenmrsUser()).thenReturn(mapped);
		when(info.getRoleNames()).thenReturn(java.util.Collections.singletonList("Organizational: Nurse"));
		UserService us = mock(UserService.class);
		when(us.getUserByUsername("nurse1")).thenReturn(existing);
		when(us.getRole("Organizational: Nurse")).thenReturn(new org.openmrs.Role("Organizational: Nurse"));
		org.mockito.Mockito.doThrow(new RuntimeException("db down")).when(us).saveUser(org.mockito.Matchers.any(User.class));
		
		UpdateUserTask task = new UpdateUserTask(us, info);
		task.run();
		
		org.junit.Assert.assertNotNull(task.getFailure());
		org.junit.Assert.assertNull("roles not saved must not reach the session", task.getAssignedRoles());
	}
}
