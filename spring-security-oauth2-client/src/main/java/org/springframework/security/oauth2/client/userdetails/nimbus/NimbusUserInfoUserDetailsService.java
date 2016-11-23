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
package org.springframework.security.oauth2.client.userdetails.nimbus;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import net.minidev.json.JSONObject;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userdetails.UserInfoUserDetailsService;
import org.springframework.security.oauth2.core.OAuth2Exception;
import org.springframework.security.oauth2.core.userdetails.OAuth2User;
import org.springframework.security.oauth2.core.userdetails.OAuth2UserAttribute;
import org.springframework.security.oauth2.core.userdetails.OAuth2UserDetails;
import org.springframework.security.openid.connect.core.OpenIDConnectAttributes;
import org.springframework.security.openid.connect.core.userdetails.OpenIDConnectUser;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author Joe Grandja
 */
public class NimbusUserInfoUserDetailsService implements UserInfoUserDetailsService {

	@Override
	public UserDetails loadUserDetails(OAuth2AuthenticationToken authenticationRequest) throws UsernameNotFoundException {
		OAuth2User oauth2User;

		try {
			URI userInfoUri = toURI(authenticationRequest.getConfiguration().getUserInfoUri());
			BearerAccessToken accessToken = new BearerAccessToken(authenticationRequest.getAccessToken().getValue());

			// Request the User Info
			UserInfoRequest userInfoRequest = new UserInfoRequest(userInfoUri, accessToken);
			HTTPRequest httpRequest = userInfoRequest.toHTTPRequest();
			httpRequest.setAccept(MediaType.APPLICATION_JSON_VALUE);
			HTTPResponse httpResponse = httpRequest.send();

			if (httpResponse.getStatusCode() != HTTPResponse.SC_OK) {
				// TODO Throw OAuth2-specific exception for downstream handling
				UserInfoErrorResponse userInfoErrorResponse = UserInfoErrorResponse.parse(httpResponse);
				throw new OAuth2Exception(userInfoErrorResponse.getErrorObject().getDescription());
			}

			if (authenticationRequest.getConfiguration().isClientOpenIDConnect()) {
				UserInfoSuccessResponse userInfoResponse = UserInfoSuccessResponse.parse(httpResponse);
				oauth2User = new OpenIDConnectUserBuilder()
						.jsonAttributes(userInfoResponse.getUserInfo().toJSONObject())
						.build();
			} else {
				oauth2User = new OAuth2UserBuilder()
						.jsonAttributes(httpResponse.getContentAsJSONObject())
						.build();
			}

		} catch (ParseException pe) {
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception(pe);
		} catch (IOException ioe) {
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception(ioe);
		}

		return oauth2User;
	}

	private URI toURI(String uriStr) throws IOException {
		try {
			return new URI(uriStr);
		} catch (URISyntaxException ex) {
			throw new IOException(ex);
		}
	}

	private class OAuth2UserBuilder extends AbstractOAuth2UserDetailsBuilder<OAuth2User> {
		static final String DEFAULT_IDENTIFIER_ATTRIBUTE_NAME = "id";

		OAuth2UserBuilder() {
			this.identifierAttributeName = DEFAULT_IDENTIFIER_ATTRIBUTE_NAME;
		}

		@Override
		OAuth2User build() {
			List<OAuth2UserAttribute> userAttributes = this.getUserAttributes();
			OAuth2UserAttribute identifierAttribute = this.findIdentifier(userAttributes);
			Set<GrantedAuthority> authorities = this.loadAuthorities(identifierAttribute);
			return new OAuth2User(identifierAttribute, userAttributes, authorities);
		}
	}

	private class OpenIDConnectUserBuilder extends AbstractOAuth2UserDetailsBuilder<OpenIDConnectUser> {

		OpenIDConnectUserBuilder() {
			this.identifierAttributeName = OpenIDConnectAttributes.Claim.SUB;
		}

		@Override
		OpenIDConnectUser build() {
			List<OAuth2UserAttribute> userAttributes = this.getUserAttributes();
			OAuth2UserAttribute identifierAttribute = this.findIdentifier(userAttributes);
			Set<GrantedAuthority> authorities = this.loadAuthorities(identifierAttribute);
			return new OpenIDConnectUser(identifierAttribute, userAttributes, authorities);
		}
	}

	private abstract class AbstractOAuth2UserDetailsBuilder<O extends OAuth2UserDetails> {
		JSONObject jsonAttributes;
		String identifierAttributeName;

		AbstractOAuth2UserDetailsBuilder<O> jsonAttributes(JSONObject jsonAttributes) {
			this.jsonAttributes = jsonAttributes;
			return this;
		}

		AbstractOAuth2UserDetailsBuilder<O> identifierAttributeName(String identifierAttributeName) {
			this.identifierAttributeName = identifierAttributeName;
			return this;
		}

		abstract O build();

		List<OAuth2UserAttribute> getUserAttributes() {
			List<OAuth2UserAttribute> userAttributes = this.jsonAttributes.entrySet().stream()
					.map(e -> new OAuth2UserAttribute(e.getKey(), e.getValue())).collect(Collectors.toList());
			return userAttributes;
		}

		OAuth2UserAttribute findIdentifier(List<OAuth2UserAttribute> userAttributes) {
			Optional<OAuth2UserAttribute> identifierAttribute = userAttributes.stream()
					.filter(e -> e.getName().equalsIgnoreCase(this.identifierAttributeName)).findFirst();
			if (!identifierAttribute.isPresent()) {
				// TODO Throw
			}
			return identifierAttribute.get();
		}

		Set<GrantedAuthority> loadAuthorities(OAuth2UserAttribute identifierAttribute) {
			Set<GrantedAuthority> authorities = Collections.emptySet();

			// TODO Load authorities - see MappableAttributesRetriever and Attributes2GrantedAuthoritiesMapper

			return authorities;
		}
	}
}