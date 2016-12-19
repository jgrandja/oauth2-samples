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
package org.springframework.security.oauth2.client.config;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * @author Joe Grandja
 */
public class InMemoryClientConfigurationRepository implements ClientConfigurationRepository {
	private final List<ClientConfiguration> clientConfigurations;

	public InMemoryClientConfigurationRepository(List<ClientConfiguration> clientConfigurations) {
		this.clientConfigurations = Collections.unmodifiableList(clientConfigurations);
	}

	@Override
	public ClientConfiguration getConfigurationById(String clientId) {
		Optional<ClientConfiguration> configuration =
				this.clientConfigurations.stream()
				.filter(c -> c.getClientId().equals(clientId))
				.findFirst();
		return configuration.isPresent() ? configuration.get() : null;
	}

	@Override
	public ClientConfiguration getConfigurationByAlias(String clientAlias) {
		Optional<ClientConfiguration> configuration =
				this.clientConfigurations.stream()
						.filter(c -> c.getClientAlias().equals(clientAlias))
						.findFirst();
		return configuration.isPresent() ? configuration.get() : null;
	}

	@Override
	public List<ClientConfiguration> getConfigurations() {
		return this.clientConfigurations;
	}
}