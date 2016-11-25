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

import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.validator.OAuthClientValidator;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.utils.JSONUtils;

import java.util.Collections;
import java.util.Map;

/**
 * @author Joe Grandja
 */
public class OltuUserInfoResponse extends OAuthClientResponse {

	public OltuUserInfoResponse() {
		this.validator = new NullOAuthClientValidator();
	}

	@Override
	protected void setBody(String body) throws OAuthProblemException {
		try {
			this.body = body;
			this.parameters = JSONUtils.parseJSON(body);
		} catch (Exception ex) {
			throw OAuthProblemException.error(ex.getMessage());
		}
	}

	@Override
	protected void setContentType(String contentType) {
		this.contentType = contentType;
	}

	@Override
	protected void setResponseCode(int responseCode) {
		this.responseCode = responseCode;
	}

	public Map<String, Object> getAttributes() {
		return Collections.unmodifiableMap(this.parameters);
	}

	private static class NullOAuthClientValidator extends OAuthClientValidator {
	}
}