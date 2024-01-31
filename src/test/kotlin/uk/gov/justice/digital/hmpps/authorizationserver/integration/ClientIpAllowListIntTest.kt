package uk.gov.justice.digital.hmpps.authorizationserver.integration

import org.junit.jupiter.api.Test
import org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED
import org.springframework.web.reactive.function.BodyInserters.fromFormData
import java.util.Base64

class ClientIpAllowListIntTest : IntegrationTestBase() {

  private val token = "test-secret"

  @Test
  fun `empty ip allow list returns token`() {
    val username = "test-client-id"
    webTestClient.post().uri("/oauth2/token")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("$username:$token").toByteArray()))
      .contentType(APPLICATION_FORM_URLENCODED)
      .body(
        fromFormData("grant_type", "client_credentials"),
      )
      .exchange()
      .expectStatus().isOk
  }

  @Test
  fun `localhost ip in allow list returns token`() {
    val username = "ip-allow-a-client-1"
    webTestClient.post().uri("/oauth2/token")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("$username:$token").toByteArray()))
      .contentType(APPLICATION_FORM_URLENCODED)
      .body(
        fromFormData("grant_type", "client_credentials"),
      )
      .exchange()
      .expectStatus().isOk
  }

  @Test
  fun `ip in allow list base client id returns token`() {
    val username = "ip-allow-b-client"
    webTestClient.post().uri("/oauth2/token")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("$username:$token").toByteArray()))
      .header("x-forwarded-for", "35.176.93.186")
      .contentType(APPLICATION_FORM_URLENCODED)
      .body(
        fromFormData("grant_type", "client_credentials"),
      )
      .exchange()
      .expectStatus().isOk
  }

  @Test
  fun `ip in allow list incremented client id returns token`() {
    val username = "ip-allow-b-client-8"
    webTestClient.post().uri("/oauth2/token")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("$username:$token").toByteArray()))
      .header("x-forwarded-for", "35.176.93.186")
      .contentType(APPLICATION_FORM_URLENCODED)
      .body(
        fromFormData("grant_type", "client_credentials"),
      )
      .exchange()
      .expectStatus().isOk
  }

  @Test
  fun `token can be retrieved when ip address uses CIDR notation in allow list`() {
    val username = "ip-allow-c-client"
    webTestClient.post().uri("/oauth2/token")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("$username:$token").toByteArray()))
      .header("x-forwarded-for", "35.176.3.1")
      .contentType(APPLICATION_FORM_URLENCODED)
      .body(
        fromFormData("grant_type", "client_credentials"),
      )
      .exchange()
      .expectStatus().isOk
  }

  @Test
  fun `localhost ip not in allow list unauthorized`() {
    val username = "ip-allow-b-client"
    webTestClient.post().uri("/oauth2/token")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("$username:$token").toByteArray()))
      .contentType(APPLICATION_FORM_URLENCODED)
      .body(
        fromFormData("grant_type", "client_credentials"),
      )
      .exchange()
      .expectStatus().isUnauthorized
  }

  @Test
  fun `base client id ip not in allow list unauthorized`() {
    val username = "ip-allow-b-client"
    webTestClient.post().uri("/oauth2/token")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("$username:$token").toByteArray()))
      .header("x-forwarded-for", "235.177.93.186")
      .contentType(APPLICATION_FORM_URLENCODED)
      .body(
        fromFormData("grant_type", "client_credentials"),
      )
      .exchange()
      .expectStatus().isUnauthorized
  }

  @Test
  fun `incremented client id ip not in allow list unauthorized`() {
    val username = "ip-allow-b-client-8"
    webTestClient.post().uri("/oauth2/token")
      .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("$username:$token").toByteArray()))
      .header("x-forwarded-for", "235.177.93.186")
      .contentType(APPLICATION_FORM_URLENCODED)
      .body(
        fromFormData("grant_type", "client_credentials"),
      )
      .exchange()
      .expectStatus().isUnauthorized
  }
}
