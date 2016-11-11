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
package org.springframework.security.oidc.rp.authentication;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2Exception;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * @author Joe Grandja
 */
public class NimbusAuthenticationUserDetailsService implements AuthenticationUserDetailsService<OpenIDConnectAuthenticationToken> {

	@Override
	public UserDetails loadUserDetails(OpenIDConnectAuthenticationToken token) throws UsernameNotFoundException {

		UserInfoResponse userInfoResponse;
		try {
			URI userInfoUri = toURI(token.getConfiguration().getUserInfoUri());
			BearerAccessToken accessToken = new BearerAccessToken(token.getAccessToken().getValue());

			// Request the User Info
			UserInfoRequest userInfoRequest = new UserInfoRequest(userInfoUri, accessToken);
			userInfoResponse = UserInfoResponse.parse(userInfoRequest.toHTTPRequest().send());
		} catch (ParseException pe) {
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception(pe);
		} catch (IOException ioe) {
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception(ioe);
		}

		if (!userInfoResponse.indicatesSuccess()) {
			// TODO Throw OAuth2-specific exception for downstream handling
			UserInfoErrorResponse userInfoErrorResponse = UserInfoErrorResponse.class.cast(userInfoResponse);
			throw new OAuth2Exception(userInfoErrorResponse.getErrorObject().getDescription());
		}

		UserInfoSuccessResponse userInfoSuccessResponse = UserInfoSuccessResponse.class.cast(userInfoResponse);

		String subject = userInfoSuccessResponse.getUserInfo().getSubject().getValue();
		String fullName = userInfoSuccessResponse.getUserInfo().getName();
		String givenName = userInfoSuccessResponse.getUserInfo().getGivenName();
		String familyName = userInfoSuccessResponse.getUserInfo().getFamilyName();
		String email = userInfoSuccessResponse.getUserInfo().getEmail().getAddress();

		OpenIDConnectUser userInfo = new OpenIDConnectUser(subject, fullName);
		userInfo.setGivenName(givenName);
		userInfo.setFamilyName(familyName);
		userInfo.setEmail(email);

		return userInfo;
	}

	private URI toURI(String uriStr) throws IOException {
		try {
			return new URI(uriStr);
		} catch (URISyntaxException ex) {
			throw new IOException(ex);
		}
	}
}