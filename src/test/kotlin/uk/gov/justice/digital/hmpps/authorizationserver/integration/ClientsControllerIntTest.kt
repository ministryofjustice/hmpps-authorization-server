package uk.gov.justice.digital.hmpps.authorizationserver.integration

import com.microsoft.applicationinsights.TelemetryClient
import org.assertj.core.api.Assertions.assertThat
import org.hamcrest.CoreMatchers
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.data.repository.findByIdOrNull
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.web.reactive.function.BodyInserters
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.AuthorizationConsent.AuthorizationConsentId
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientConfigRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientDeploymentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientRepository
import uk.gov.justice.digital.hmpps.authorizationserver.service.RegisteredClientAdditionalInformation
import uk.gov.justice.digital.hmpps.authorizationserver.utils.OAuthClientSecret
import java.time.Duration
import java.time.LocalDate
import java.util.Base64.getEncoder

class ClientsControllerIntTest : IntegrationTestBase() {

  @Autowired
  lateinit var clientConfigRepository: ClientConfigRepository

  @Autowired
  lateinit var clientRepository: ClientRepository

  @Autowired
  lateinit var authorizationConsentRepository: AuthorizationConsentRepository

  @Autowired
  lateinit var clientDeploymentRepository: ClientDeploymentRepository

  @MockBean
  lateinit var oAuthClientSecretGenerator: OAuthClientSecret

  @MockBean
  private lateinit var telemetryClient: TelemetryClient

  @Autowired
  lateinit var jdbcRegisteredClientRepository: JdbcRegisteredClientRepository

  @Nested
  inner class ListAllClients {
    @Test
    fun `access forbidden when no authority`() {
      webTestClient.get().uri("/base-clients")
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.get().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.get().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `list clients success`() {
      webTestClient.get().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectHeader().contentType(MediaType.APPLICATION_JSON)
        .expectBody()
        .jsonPath("$.clients[4].baseClientId").isEqualTo("test-client-id")
        .jsonPath("$.clients[4].clientType").isEqualTo("PERSONAL")
        .jsonPath("$.clients[4].teamName").isEqualTo("HAAR")
        .jsonPath("$.clients[4].grantType").isEqualTo("client_credentials")
        .jsonPath("$.clients[4].roles").isEqualTo("AUDIT\nOAUTH_ADMIN\nTESTING")
        .jsonPath("$.clients[4].count").isEqualTo(1)
        .jsonPath("$.clients[4].expired").isEmpty
        .jsonPath("$.clients[*].baseClientId").value<List<String>> { assertThat(it).hasSize(5) }
        .jsonPath("$.clients[*].baseClientId").value<List<String>> {
          assertThat(it).containsAll(
            listOf(
              "ip-allow-a-client",
              "ip-allow-b-client",
              "ip-allow-c-client",
              "test-client-create-id",
              "test-client-id",
            ),
          )
        }
    }

    @Test
    fun `list clients filtered by roles, grantType and clientType`() {
      webTestClient.get().uri("/base-clients?role=AUDIT&grantType=client_credentials&clientType=PERSONAL")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectHeader().contentType(MediaType.APPLICATION_JSON)
        .expectBody()
        .jsonPath("$.clients[0].baseClientId").isEqualTo("test-client-id")
        .jsonPath("$.clients[0].clientType").isEqualTo("PERSONAL")
        .jsonPath("$.clients[0].teamName").isEqualTo("HAAR")
        .jsonPath("$.clients[0].grantType").isEqualTo("client_credentials")
        .jsonPath("$.clients[0].roles").isEqualTo("AUDIT\nOAUTH_ADMIN\nTESTING")
        .jsonPath("$.clients[0].count").isEqualTo(1)
        .jsonPath("$.clients[0].expired").isEmpty
        .jsonPath("$.clients[*].baseClientId").value<List<String>> { assertThat(it).hasSize(1) }
        .jsonPath("$.clients[*].baseClientId").value<List<String>> {
          assertThat(it).containsAll(
            listOf(
              "test-client-id",
            ),
          )
        }
    }
  }

  @Nested
  inner class DeleteClient {
    @Test
    fun `access forbidden when no authority`() {
      webTestClient.delete().uri("/clients/test-client-id/delete")
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.delete().uri("/clients/test-client-id/delete")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.delete().uri("/clients/test-client-id/delete")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `unrecognised client id`() {
      webTestClient.delete().uri("/clients/test-test/delete")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `delete success single client version only`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")
      givenANewClientExistsWithClientId("test-test")

      webTestClient.delete().uri("/clients/test-test/delete")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk

      assertNull(clientRepository.findClientByClientId("test-test"))
      assertNull(clientDeploymentRepository.findClientDeploymentByBaseClientId("test-test"))
      assertFalse(clientConfigRepository.findById("test-test").isPresent)

      verify(telemetryClient).trackEvent(
        "AuthorizationServerClientDeleted",
        mapOf("username" to "AUTH_ADM", "clientId" to "test-test"),
        null,
      )
    }

    @Test
    fun `delete success multiple client versions`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret").thenReturn("external-client-secret-2")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret-2")).thenReturn("encoded-client-secret-2")

      givenANewClientExistsWithClientId("test-test")

      webTestClient.post().uri("/clients/test-test/duplicate")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk

      webTestClient.delete().uri("/clients/test-test-1/delete")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk

      assertNull(clientRepository.findClientByClientId("test-test-1"))

      val baseClient = clientRepository.findClientByClientId("test-test")
      val clientDeployment = clientDeploymentRepository.findClientDeploymentByBaseClientId("test-test")
      val clientConfig = clientConfigRepository.findById("test-test")

      assertNotNull(baseClient)
      assertNotNull(clientDeployment)
      assertTrue(clientConfig.isPresent)

      clientDeploymentRepository.delete(clientDeployment)
      clientConfigRepository.delete(clientConfig.get())
      clientRepository.delete(baseClient)

      verify(telemetryClient).trackEvent(
        "AuthorizationServerClientDeleted",
        mapOf("username" to "AUTH_ADM", "clientId" to "test-test-1"),
        null,
      )
    }

    private fun givenANewClientExistsWithClientId(clientId: String) {
      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to clientId,
              "clientName" to "testing testing",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest-1",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValidity" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      webTestClient.post().uri("/clients/$clientId/deployment")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientType" to "PERSONAL",
              "team" to "testing team",
              "teamContact" to "testy lead",
              "teamSlack" to "#testy",
              "hosting" to "CLOUDPLATFORM",
              "namespace" to "testy-testing-dev",
              "deployment" to "hmpps-testing-dev",
              "secretName" to "hmpps-testing",
              "clientIdKey" to "SYSTEM_CLIENT_ID",
              "secretKey" to "SYSTEM_CLIENT_SECRET",
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk

      assertNotNull(clientRepository.findClientByClientId("test-test"))
      assertNotNull(clientDeploymentRepository.findClientDeploymentByBaseClientId("test-test"))
      assertTrue(clientConfigRepository.findById("test-test").isPresent)
    }
  }

  @Nested
  inner class ClientExists {
    @Test
    fun `access forbidden when no authority`() {
      webTestClient.get().uri("/clients/exists/test-client-id")
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.get().uri("/clients/exists/test-client-id")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.get().uri("/clients/exists/test-client-id")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `unrecognised client id`() {
      webTestClient.get().uri("/clients/exists/test-test")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_CLIENTS_VIEW")))
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `client exists`() {
      webTestClient.get().uri("/clients/exists/test-client-id")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_CLIENTS_VIEW")))
        .exchange()
        .expectStatus().isOk
        .expectHeader().contentType(MediaType.APPLICATION_JSON)
        .expectBody()
        .jsonPath("$.clientId").isEqualTo("test-client-id")
        .jsonPath("$.accessTokenValidityMinutes").isEqualTo(5)
    }
  }

  @Nested
  inner class ListCopies {
    @Test
    fun `access forbidden when no authority`() {
      webTestClient.get().uri("/clients/duplicates/test-client-id")
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.get().uri("/clients/duplicates/test-client-id")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.get().uri("/clients/duplicates/test-client-id")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `unrecognised client id`() {
      webTestClient.get().uri("clients/duplicates/test-test")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `lists multiple copies ordered by client id`() {
      webTestClient.get().uri("/clients/duplicates/ip-allow-b-client-8")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("$.clients[*].clientId").value<List<String>> { assertThat(it).hasSize(2) }
        .jsonPath("$.clients[*].clientId").value<List<String>> {
          assertThat(it).containsExactly(
            "ip-allow-b-client",
            "ip-allow-b-client-8",
          )
        }
        .jsonPath("$.clients[0].clientId").isEqualTo("ip-allow-b-client")
        .jsonPath("$.clients[0].created").isNotEmpty
        .jsonPath("$.clients[0].lastAccessed").isNotEmpty
    }

    @Test
    fun `returns single client when no other copies`() {
      webTestClient.get().uri("/clients/duplicates/test-client-id")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("$.clients[*].clientId").value<List<String>> { assertThat(it).hasSize(1) }
        .jsonPath("$.clients[*].clientId").value<List<String>> {
          assertThat(it).containsExactly(
            "test-client-id",
          )
        }
    }
  }

  @Nested
  inner class DuplicateClient {

    @Test
    fun `access forbidden when no authority`() {
      webTestClient.post().uri("/clients/test-client-id/duplicate")
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.post().uri("/clients/test-client-id/duplicate")
        .headers(setAuthorisation(roles = listOf()))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.post().uri("/clients/test-client-id/duplicate")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `not found when no clients exist for base client id`() {
      webTestClient.post().uri("/clients/test-client-x-id/duplicate")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isNotFound
    }

    @Test
    fun `conflict when the maximum number of clients already exist for base client id`() {
      whenever(oAuthClientSecretGenerator.generate())
        .thenReturn("external-client-secret")
        .thenReturn("external-client-secret-2")
        .thenReturn("external-client-secret-3")

      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret-2")).thenReturn("encoded-client-secret-2")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret-3")).thenReturn("encoded-client-secret-3")

      webTestClient.post().uri("/clients/test-client-id/duplicate")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk

      webTestClient.post().uri("/clients/test-client-id/duplicate")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk

      val duplicatedClient = clientRepository.findClientByClientId("test-client-id-1")
      val duplicatedClient2 = clientRepository.findClientByClientId("test-client-id-2")

      webTestClient.post().uri("/clients/test-client-id/duplicate")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isEqualTo(HttpStatus.CONFLICT)

      clientRepository.delete(duplicatedClient)
      clientRepository.delete(duplicatedClient2)
    }

    @Test
    fun `duplicate success`() {
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/clients/test-client-id/duplicate")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo("test-client-id-1")
        .jsonPath("clientSecret").isEqualTo("external-client-secret")
        .jsonPath("base64ClientId").isEqualTo(getEncoder().encodeToString("test-client-id-1".toByteArray()))
        .jsonPath("base64ClientSecret").isEqualTo(getEncoder().encodeToString("external-client-secret".toByteArray()))

      val originalClient = clientRepository.findClientByClientId("test-client-id")
      val duplicatedClient = clientRepository.findClientByClientId("test-client-id-1")
      assertThat(duplicatedClient!!.clientName).isEqualTo(originalClient!!.clientName)
      assertThat(duplicatedClient.scopes).isEqualTo(originalClient.scopes)
      assertThat(duplicatedClient.authorizationGrantTypes).isEqualTo(originalClient.authorizationGrantTypes)
      assertThat(duplicatedClient.clientAuthenticationMethods).isEqualTo(originalClient.clientAuthenticationMethods)
      assertThat(duplicatedClient.clientSettings).isEqualTo(originalClient.clientSettings)
      assertThat(duplicatedClient.tokenSettings).isEqualTo(originalClient.tokenSettings)

      val authorizationConsent = authorizationConsentRepository.findByIdOrNull(AuthorizationConsentId(originalClient.id, originalClient.clientId))
      val duplicateCateAuthorizationConsent = authorizationConsentRepository.findByIdOrNull(AuthorizationConsent.AuthorizationConsentId(duplicatedClient.id, duplicatedClient.clientId))

      assertThat(duplicateCateAuthorizationConsent?.authorities).isEqualTo(authorizationConsent?.authorities)

      authorizationConsentRepository.delete(duplicateCateAuthorizationConsent)

      verify(telemetryClient).trackEvent(
        "AuthorizationServerClientDetailsDuplicated",
        mapOf("username" to "AUTH_ADM", "clientId" to "test-client-id-1"),
        null,
      )

      clientRepository.delete(duplicatedClient)
    }
  }

  @Nested
  inner class AddClient {

    @Test
    fun `access forbidden when no authority`() {
      webTestClient.post().uri("/base-clients")
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "clientName" to "test client",
              "scopes" to listOf("read"),
              "authorities" to listOf("VIEW_PRISONER_DATA"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when no role`() {
      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf()))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "clientName" to "test client",
              "scopes" to listOf("read"),
              "authorities" to listOf("VIEW_PRISONER_DATA"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `access forbidden when wrong role`() {
      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("WRONG")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "clientName" to "test client",
              "scopes" to listOf("read"),
              "authorities" to listOf("VIEW_PRISONER_DATA"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isForbidden
    }

    @Test
    fun `bad request when client already exists`() {
      assertNotNull(jdbcRegisteredClientRepository.findByClientId("test-client-id"))

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "test-client-id",
              "clientName" to "test client",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isBadRequest
        .expectBody()
        .json(
          """
              {
              "userMessage":"Client with client id test-client-id cannot be created as already exists",
              "developerMessage":"Client with client id test-client-id cannot be created as already exists"
              }
          """
            .trimIndent(),
        )
    }

    @Test
    fun `bad request when client with same base client id already exists`() {
      assertNotNull(jdbcRegisteredClientRepository.findByClientId("ip-allow-a-client-1"))
      assertNull(jdbcRegisteredClientRepository.findByClientId("ip-allow-a-client"))

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "ip-allow-a-client",
              "clientName" to "test client",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
            ),
          ),
        )
        .exchange()
        .expectStatus().isBadRequest
        .expectBody()
        .json(
          """
              {
              "userMessage":"Client with client id ip-allow-a-client cannot be created as already exists",
              "developerMessage":"Client with client id ip-allow-a-client cannot be created as already exists"
              }
          """
            .trimIndent(),
        )
    }

    @Test
    fun `register client success`() {
      assertNull(clientRepository.findClientByClientId("testy"))
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValidityMinutes" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo("testy")
        .jsonPath("clientSecret").isEqualTo("external-client-secret")
        .jsonPath("base64ClientId").isEqualTo(getEncoder().encodeToString("testy".toByteArray()))
        .jsonPath("base64ClientSecret").isEqualTo(getEncoder().encodeToString("external-client-secret".toByteArray()))

      val client = clientRepository.findClientByClientId("testy")

      assertNotNull(client)
      assertThat(client!!.clientId).isEqualTo("testy")
      assertThat(client.clientName).isEqualTo("testy")
      assertThat(client.clientSecret).isEqualTo("encoded-client-secret")
      assertThat(client.authorizationGrantTypes).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS.value)
      assertThat(client.scopes).contains("read", "write")
      assertThat(client.tokenSettings.accessTokenTimeToLive).isEqualTo(Duration.ofMinutes(20))
      assertThat(client.tokenSettings.settings[RegisteredClientAdditionalInformation.DATABASE_USER_NAME_KEY]).isEqualTo("testy-mctest")
      assertThat(client.tokenSettings.settings[RegisteredClientAdditionalInformation.JIRA_NUMBER_KEY]).isEqualTo("HAAR-9999")

      val clientConfig = clientConfigRepository.findById(client.clientId).get()
      assertThat(clientConfig.ips).contains("81.134.202.29/32", "35.176.93.186/32")
      assertThat(clientConfig.clientEndDate).isEqualTo(LocalDate.now().plusDays(4))
      val authorizationConsent =
        verifyAuthorities(client.id!!, client.clientId, "ROLE_CURIOUS_API", "ROLE_VIEW_PRISONER_DATA", "ROLE_COMMUNITY")

      verify(telemetryClient).trackEvent(
        "AuthorizationServerDetailsAdd",
        mapOf("username" to "AUTH_ADM", "clientId" to "testy"),
        null,
      )

      clientRepository.delete(client)
      clientConfigRepository.delete(clientConfig)
      authorizationConsentRepository.delete(authorizationConsent)
    }

    @Test
    fun `register incomplete client`() {
      assertNull(clientRepository.findClientByClientId("testy"))
      whenever(oAuthClientSecretGenerator.generate()).thenReturn("external-client-secret")
      whenever(oAuthClientSecretGenerator.encode("external-client-secret")).thenReturn("encoded-client-secret")

      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "clientId" to "testy",
            ),
          ),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("clientId").isEqualTo("testy")
        .jsonPath("clientSecret").isEqualTo("external-client-secret")

      val client = clientRepository.findClientByClientId("testy")

      assertNotNull(client)
      assertThat(client!!.clientId).isEqualTo("testy")
      assertThat(client.clientName).isEqualTo("testy")
      assertThat(client.clientSecret).isEqualTo("encoded-client-secret")
      assertThat(client.authorizationGrantTypes).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS.value)
      assertThat(client.scopes).containsOnly("read")
      assertFalse(clientConfigRepository.findById(client.clientId).isPresent)
      assertFalse(authorizationConsentRepository.findById(AuthorizationConsent.AuthorizationConsentId(client.id, client.clientId)).isPresent)

      verify(telemetryClient).trackEvent(
        "AuthorizationServerDetailsAdd",
        mapOf("username" to "AUTH_ADM", "clientId" to "testy"),
        null,
      )

      clientRepository.delete(client)
    }

    @Test
    fun `omit mandatory fields gives bad request response`() {
      webTestClient.post().uri("/base-clients")
        .headers(setAuthorisation(roles = listOf("ROLE_OAUTH_ADMIN")))
        .body(
          BodyInserters.fromValue(
            mapOf(
              "scopes" to listOf("read", "write"),
              "authorities" to listOf("CURIOUS_API", "VIEW_PRISONER_DATA", "COMMUNITY"),
              "ips" to listOf("81.134.202.29/32", "35.176.93.186/32"),
              "databaseUserName" to "testy-mctest",
              "jiraNumber" to "HAAR-9999",
              "validDays" to 5,
              "accessTokenValidityMinutes" to 20,
            ),
          ),
        )
        .exchange()
        .expectStatus().isBadRequest
        .expectBody().jsonPath("errors").value(
          CoreMatchers.hasItems("clientId must not be blank"),
        )
    }
  }
  private fun verifyAuthorities(id: String, clientId: String, vararg authorities: String): AuthorizationConsent {
    val authorizationConsent = authorizationConsentRepository.findById(AuthorizationConsent.AuthorizationConsentId(id, clientId)).get()
    assertThat(authorizationConsent.authorities).containsOnly(*authorities)
    return authorizationConsent
  }
}
