package uk.gov.justice.digital.hmpps.authorizationserver.service.converter

import org.springframework.core.convert.converter.Converter
import org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS
import org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.Client
import uk.gov.justice.digital.hmpps.authorizationserver.resource.MigrationClientRequest
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientIdService
import uk.gov.justice.digital.hmpps.authorizationserver.service.RegisteredClientAdditionalInformation

@Component
class MigrationClientConverter(
  private val registeredClientAdditionalInformation: RegisteredClientAdditionalInformation,
  private val clientIdService: ClientIdService,
) : Converter<MigrationClientRequest, Client> {
  override fun convert(source: MigrationClientRequest): Client {
    with(source) {
      return Client(
        id = java.util.UUID.randomUUID().toString(),
        clientId = clientId!!,
        clientIdIssuedAt = java.time.Instant.now(),
        clientSecretExpiresAt = null,
        clientName = clientIdService.toBase(clientId),
        clientAuthenticationMethods = CLIENT_SECRET_BASIC.value,
        authorizationGrantTypes = CLIENT_CREDENTIALS.value,
        scopes = scopes ?: listOf("read"),
        clientSettings =
        org.springframework.security.oauth2.server.authorization.settings.ClientSettings.builder()
          .requireProofKey(false)
          .requireAuthorizationConsent(false).build(),
        tokenSettings = registeredClientAdditionalInformation.buildTokenSettings(accessTokenValidityMinutes, databaseUserName, jiraNumber),
        latestClientAuthorization = mutableSetOf(),
      )
    }
  }
}
