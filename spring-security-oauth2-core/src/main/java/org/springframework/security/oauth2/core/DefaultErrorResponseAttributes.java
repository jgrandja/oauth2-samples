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
package org.springframework.security.oauth2.core;

import java.net.URI;

/**
 * @author Joe Grandja
 */
public class DefaultErrorResponseAttributes implements ErrorResponseAttributes {
	private final String errorCode;
	private final String errorDescription;
	private final URI errorUri;

	public DefaultErrorResponseAttributes(String errorCode) {
		this(errorCode, null, null);
	}

	public DefaultErrorResponseAttributes(String errorCode, String errorDescription, URI errorUri) {
		this.errorCode = errorCode;
		this.errorDescription = errorDescription;
		this.errorUri = errorUri;
	}

	@Override
	public final String getErrorCode() {
		return this.errorCode;
	}

	@Override
	public final String getErrorDescription() {
		return this.errorDescription;
	}

	@Override
	public final URI getErrorUri() {
		return this.errorUri;
	}
}