package uk.gov.justice.digital.hmpps.authorizationserver.utils

import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator
import org.springframework.security.crypto.keygen.StringKeyGenerator
import org.springframework.stereotype.Component
import java.util.Base64

@Component
class OAuthClientSecret {

  private val clientSecretGenerator: StringKeyGenerator = Base64StringKeyGenerator(
    Base64.getUrlEncoder().withoutPadding(),
    48,
  )

  private val passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()

  fun generate(): String {
    return clientSecretGenerator.generateKey()
  }

  fun encode(secret: String): String {
    return passwordEncoder.encode(secret)
  }
}