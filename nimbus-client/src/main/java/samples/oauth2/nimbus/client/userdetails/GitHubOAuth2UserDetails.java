/*
 * Copyright 2012-2017 the original author or authors.
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
package samples.oauth2.nimbus.client.userdetails;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.userdetails.OAuth2UserAttribute;
import org.springframework.security.oauth2.core.userdetails.OAuth2UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * @author Joe Grandja
 */
public class GitHubOAuth2UserDetails implements OAuth2UserDetails {
	private String id;
	private String name;
	private String login;
	private String email;

	public GitHubOAuth2UserDetails() {
	}

	@Override
	public OAuth2UserAttribute getIdentifier() {
		OAuth2UserAttribute identifier = new OAuth2UserAttribute("id", this.id);
		return identifier;
	}

	@Override
	public List<OAuth2UserAttribute> getAttributes() {
		List<OAuth2UserAttribute> attributes = new ArrayList<>();
		attributes.add(new OAuth2UserAttribute("id", this.id));
		attributes.add(new OAuth2UserAttribute("name", this.name));
		attributes.add(new OAuth2UserAttribute("login", this.login));
		attributes.add(new OAuth2UserAttribute("email", this.email));
		return attributes;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return Collections.emptyList();
	}

	@Override
	public String getPassword() {
		return null;
	}

	@Override
	public String getUsername() {
		return this.login;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getLogin() {
		return login;
	}

	public void setLogin(String login) {
		this.login = login;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}
}