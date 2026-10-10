package org.openmrs.module.oauth2login.authscheme;

import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.beanutils.BeanUtilsBean;
import org.openmrs.Person;
import org.openmrs.PersonName;
import org.openmrs.Role;
import org.openmrs.User;
import org.openmrs.api.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.util.ClassUtils;

public class UpdateUserTask implements Runnable {
	
	private final static Logger log = LoggerFactory.getLogger(UpdateUserTask.class);
	
	private UserService userService;
	
	private UserInfo userInfo;
	
	private volatile Set<Role> assignedRoles;
	
	private volatile Throwable failure;
	
	public UpdateUserTask(UserService userService, UserInfo userInfo) {
		this.userService = userService;
		this.userInfo = userInfo;
	}
	
	/**
	 * The roles written by {@link #run()}, or null when the token carries no roles (roles left
	 * unchanged).
	 */
	public Set<Role> getAssignedRoles() {
		return assignedRoles;
	}
	
	/**
	 * Why run() failed, or null. Daemon.runInDaemonThreadAndWait swallows a task's exceptions, so
	 * it is kept here.
	 */
	public Throwable getFailure() {
		return failure;
	}
	
	@Override
	public void run() {
		try {
			User user = userService.getUserByUsername(userInfo.getUsername());
			// getUserByUsername also matches system_id; only ever update the account with this username
			if (user == null || user.getUsername() == null || !user.getUsername().equalsIgnoreCase(userInfo.getUsername())) {
				throw new IllegalStateException("OAuth2 user update: no account with this username");
			}
			Set<Role> roles = userInfo.getRoleNames() == null ? null : resolveRoles();
			userService.saveUser(updated(user, roles));
			assignedRoles = roles; // only once they are in the database (KC-58-06)
		}
		catch (Throwable t) {
			failure = t;
		}
	}
	
	private Set<Role> resolveRoles() {
		return userInfo.getRoleNames().stream().map(roleName -> userService.getRole(roleName)).filter(r -> r != null)
		        .collect(Collectors.toSet());
	}
	
	/**
	 * A bean utils bean to copy over non-null values from a bean to another. Nested non-primitive
	 * types are handled recursively.
	 * 
	 * @see https://stackoverflow.com/a/3521314/321797
	 */
	static class NullAwareBeanUtilsBean extends BeanUtilsBean {
		
		private boolean isPrimitiveType(Object obj) {
			return ClassUtils.isPrimitiveOrWrapper(obj.getClass()) || obj instanceof String;
		}
		
		private void copyCollection(Collection<?> dest, Collection<?> value) throws IllegalAccessException,
		        InvocationTargetException {
			if (dest.size() > 1 || value.size() > 1) {
				// TODO: log an appropriate error, or even throw
				return;
			}
			
			Object d = dest.stream().findFirst().orElse(null);
			Object v = value.stream().findFirst().orElse(null);
			
			if (v == null) {
				dest.clear();
			} else if (isPrimitiveType(v) || d == null) {
				dest = value;
			} else {
				new NullAwareBeanUtilsBean().copyProperties(d, v);
			}
		}
		
		@Override
		public void copyProperty(Object dest, String name, Object value) throws IllegalAccessException,
		        InvocationTargetException {
			if (value == null) {
				return;
			}
			
			Object destPropertyValue = new BeanWrapperImpl(dest).getPropertyValue(name);
			if (value.equals(destPropertyValue)) {
				return;
			}
			
			if (isPrimitiveType(value) || destPropertyValue == null) {
				super.copyProperty(dest, name, value);
			} else if (Collection.class.isAssignableFrom(destPropertyValue.getClass())) {
				copyCollection((Collection<?>) destPropertyValue, (Collection<?>) value);
			} else if (destPropertyValue.getClass().isArray()) {
				// TODO: handle arrays
			} else {
				new NullAwareBeanUtilsBean().copyProperties(destPropertyValue, value);
			}
		}
	}
	
	/**
	 * Gender and the preferred name, as mapped from the user info; fields the token does not carry
	 * stay as they are.
	 */
	static void copyMappedPersonFields(Person from, Person to) {
		if (from == null || to == null) {
			return;
		}
		if (from.getGender() != null) {
			to.setGender(from.getGender());
		}
		PersonName name = from.getPersonName();
		if (name == null) {
			return;
		}
		PersonName current = to.getPersonName();
		if (current == null) {
			to.addName(name);
			return;
		}
		if (name.getGivenName() != null) {
			current.setGivenName(name.getGivenName());
		}
		if (name.getMiddleName() != null) {
			current.setMiddleName(name.getMiddleName());
		}
		if (name.getFamilyName() != null) {
			current.setFamilyName(name.getFamilyName());
		}
	}
	
	/**
	 * Returns the updated user as per the user info.
	 * 
	 * @param user The user to update
	 * @return The updated user.
	 */
	private User updated(User user, Set<Role> roles) {
		
		try {
			User openmrsUser = userInfo.getOpenmrsUser();
			// UUIDs should be stable
			if (user.getUuid() != null) {
				openmrsUser.setUuid(user.getUuid());
			}
			
			if (user.getPerson() != null && user.getPerson().getUuid() != null) {
				openmrsUser.getPerson().setUuid(user.getPerson().getUuid());
			}
			
			if (user.getPerson() != null && user.getPerson().getPersonName() != null && user.getPerson().getPersonName().getUuid() != null) {
				openmrsUser.getPerson().getPersonName().setUuid(user.getPerson().getPersonName().getUuid());
			}
			
			new NullAwareBeanUtilsBean().copyProperties(user, openmrsUser);
			// The copy above skips the person: OpenMRS objects are equal by uuid and the uuids were just made equal, so
			// a name or gender changed in Keycloak never reached an existing (e.g. linked) account. Copy those fields.
			copyMappedPersonFields(openmrsUser.getPerson(), user.getPerson());
		}
		catch (IllegalAccessException | InvocationTargetException e) {
			log.error("Something went wrong when copying attributes from the user info to the OpenMRS user, the OpenMRS user might not have been updated properly.", e);
		}
		
		if (roles != null) {
			user.setRoles(new HashSet<>(roles));
		}
		
		return user;
	}
}
