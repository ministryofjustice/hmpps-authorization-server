package uk.gov.justice.digital.hmpps.authorizationserver.integration

import org.assertj.core.api.Assertions.assertThat
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.BodyInserters.fromFormData
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationserver.service.RegisteredClientAdditionalInformation
import java.util.Base64

class OidcIntTest : IntegrationTestBase() {

  @Autowired
  lateinit var clientRepository: ClientRepository

  @Nested
  inner class Registration {

    @Test
    fun `should register client using given client id`() {
      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token")
        .header(
          HttpHeaders.AUTHORIZATION,
          "Basic " + Base64.getEncoder().encodeToString(("test-client-create-id:test-secret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(fromFormData("grant_type", "client_credentials"))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .returnResult().responseBody

      val accessToken = JSONObject(String(clientCredentialsResponse)).get("access_token")

      webTestClient
        .post().uri("/connect/register")
        .header(HttpHeaders.AUTHORIZATION, "Bearer $accessToken")
        .body(
          BodyInserters.fromValue(
            mapOf(
              "client_id" to "authorization_code_register_test",
              "client_name" to "authorization_code_registration_test",
              "access_token_validity" to "1200",
              "scope" to "read write",
              "authorities" to "MAINTAIN_OAUTH_USERS,AUTH_GROUP_MANAGER",
              "token_endpoint_auth_method" to "client_secret_basic",
              "jwks_uri" to "https://client.example.org/my_public_keys.jwks",
              "grant_types" to "authorization_code",
              "redirect_uris" to "http://localhost:3000",
              "jira_number" to "HAAR-1999",
              "response_types" to "id_token",
            ),
          ),
        )
        .exchange()
        .expectStatus().isCreated

      val registeredClient = clientRepository.findClientByClientId("authorization_code_register_test")
      assertNotNull(registeredClient)
      assertThat(registeredClient!!.tokenSettings.settings[RegisteredClientAdditionalInformation.JIRA_NUMBER_KEY]).isEqualTo("HAAR-1999")
    }
  }
}
