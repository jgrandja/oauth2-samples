/*
 * Copyright 2012-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.core.userdetails;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

import java.util.*;

/**
 * @author Joe Grandja
 */
public class OAuth2User implements OAuth2UserDetails {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final OAuth2UserAttribute identifier;
	private final List<OAuth2UserAttribute> attributes;
	private final Set<GrantedAuthority> authorities;
	private final boolean accountNonExpired;
	private final boolean accountNonLocked;
	private final boolean credentialsNonExpired;
	private final boolean enabled;

	public OAuth2User(OAuth2UserAttribute identifier, List<OAuth2UserAttribute> attributes) {
		this(identifier, attributes, Collections.emptySet());
	}

	public OAuth2User(OAuth2UserAttribute identifier, List<OAuth2UserAttribute> attributes, Set<GrantedAuthority> authorities) {
		this(identifier, attributes, authorities, true, true, true, true);
	}


	public OAuth2User(OAuth2UserAttribute identifier, List<OAuth2UserAttribute> attributes, Set<GrantedAuthority> authorities,
					  boolean accountNonExpired, boolean accountNonLocked, boolean credentialsNonExpired, boolean enabled) {

		this.identifier = identifier;
		this.attributes = Collections.unmodifiableList(attributes);
		this.authorities = Collections.unmodifiableSet(authorities);		// TODO Sort
		this.accountNonExpired = accountNonExpired;
		this.accountNonLocked = accountNonLocked;
		this.credentialsNonExpired = credentialsNonExpired;
		this.enabled = enabled;
	}

	@Override
	public OAuth2UserAttribute getIdentifier() {
		return this.identifier;
	}

	@Override
	public List<OAuth2UserAttribute> getAttributes() {
		return this.attributes;
	}

	public OAuth2UserAttribute getAttribute(String name) {
		Optional<OAuth2UserAttribute> userAttribute = this.getAttributes().stream()
				.filter(e -> e.getName().equalsIgnoreCase(name)).findFirst();
		return (userAttribute.isPresent() ? userAttribute.get() : null);
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public String getPassword() {
		// TODO Always null...return null or string identifier? For example, n/a
		return null;
	}

	@Override
	public String getUsername() {
		// TODO Not the same as identifier...typically email address
		return null;
	}

	@Override
	public boolean isAccountNonExpired() {
		return this.accountNonExpired;
	}

	@Override
	public boolean isAccountNonLocked() {
		return this.accountNonLocked;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return this.credentialsNonExpired;
	}

	@Override
	public boolean isEnabled() {
		return this.enabled;
	}
}