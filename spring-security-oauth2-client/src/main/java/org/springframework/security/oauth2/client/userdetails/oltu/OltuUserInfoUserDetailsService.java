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
package org.springframework.security.oauth2.client.userdetails.oltu;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userdetails.UserInfoUserDetailsService;
import org.springframework.security.oauth2.core.OAuth2Exception;
import org.springframework.security.oauth2.core.userdetails.OAuth2User;
import org.springframework.security.oauth2.core.userdetails.OAuth2UserBuilder;
import org.springframework.security.openid.connect.core.userdetails.OpenIDConnectUserBuilder;

/**
 * @author Joe Grandja
 */
public class OltuUserInfoUserDetailsService implements UserInfoUserDetailsService {

	@Override
	public UserDetails loadUserDetails(OAuth2AuthenticationToken authenticationRequest) throws UsernameNotFoundException {
		OAuth2User oauth2User;

		try {
			OAuthClientRequest userInfoRequest = OltuUserInfoRequest
					.userInfoLocation(authenticationRequest.getClientRegistration().getUserInfoUri())
					.accessToken(authenticationRequest.getAccessToken().getValue())
					.buildHeaderMessage();
			userInfoRequest.setHeader("Accept", MediaType.APPLICATION_JSON_VALUE);

			// Request the User Info
			OAuthClient oauthClient = new OAuthClient(new URLConnectionClient());
			OltuUserInfoResponse userInfoResponse = oauthClient.resource(
					userInfoRequest, "GET", OltuUserInfoResponse.class);

			if (authenticationRequest.getClientRegistration().isClientOpenIDConnect()) {
				oauth2User = new OpenIDConnectUserBuilder()
						.userAttributes(userInfoResponse.getAttributes())
						.build();
			} else {
				oauth2User = new OAuth2UserBuilder()
						.userAttributes(userInfoResponse.getAttributes())
						.build();
			}

		} catch (OAuthProblemException pe) {
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception(pe.getMessage(), pe);
		} catch (OAuthSystemException se) {
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception(se.getMessage(), se);
		}

		return oauth2User;
	}
}