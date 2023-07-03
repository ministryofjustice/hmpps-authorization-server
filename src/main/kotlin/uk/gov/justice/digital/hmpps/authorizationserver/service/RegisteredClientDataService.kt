package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientRepository

@Transactional
@Service
class RegisteredClientDataService(private val clientRepository: ClientRepository) {

  fun updateAdditionalInformation(clientId: String, additionalInformation: Map<String, Any>) {
    val registeredClient = clientRepository.findClientByClientId(clientId)
    registeredClient?.let { client ->
      if (additionalInformation.isNotEmpty()) {
        client.additionalInformation = additionalInformation
      }
    }
  }
}
