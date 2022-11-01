package burp

import com.github.shamil.Xid
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.MGF1ParameterSpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec
import kotlin.math.ceil


class Client {
    private var privateKey: PrivateKey? = null
    private var publicKey: PublicKey? = null
    private val callbacks: IBurpExtenderCallbacks = BurpExtender.callbacks
    private var secretKey: String? = null
    private var correlationId: String = ""

    private var host = Config.host
    private var port = Config.port
    private var useHttps = Config.useHttps
    private var authorization = Config.auth

    fun registerClient(): Boolean {
        val pubKey = Base64.getEncoder().encodeToString(getPublicKey().toByteArray(StandardCharsets.UTF_8))
        secretKey = UUID.randomUUID().toString()
        correlationId = Xid.get().toString()
        try {
            val registerData = JSONObject()
            registerData.put("public-key", pubKey)
            registerData.put("secret-key", secretKey)
            registerData.put("correlation-id", correlationId)
            var request = """
                POST /register HTTP/1.1
                Host: $host
                User-Agent: Interact.sh Client
                Content-Type: application/json
                Content-Length: ${registerData.toString().length}
                
                """.trimIndent()
            if (authorization.isNotEmpty()) {
                request += "Authorization: $authorization\r\n"
            }
            request += """
                Connection: close
                
                $registerData
                """.trimIndent()
            val response = callbacks.makeHttpRequest(host, port, useHttps, request.toByteArray(StandardCharsets.UTF_8))
            val responseInfo = BurpExtender.analyzeResponse(response)
            if (responseInfo.statusCode.toInt() == 200) {
                return true
            }
        } catch (ex: Exception) {
            callbacks.printOutput(ex.message)
        }
        return false
    }

    fun poll(): Boolean {
        var request = """GET /poll?id=$correlationId&secret=$secretKey HTTP/1.1
Host: $host
User-Agent: Interact.sh Client
"""
        if (authorization.isNotEmpty()) {
            request += "Authorization: $authorization\r\n"
        }
        request += "Connection: close\r\n\r\n"
        val response = callbacks.makeHttpRequest(host, port, useHttps, request.toByteArray(StandardCharsets.UTF_8))
        val responseInfo = BurpExtender.analyzeResponse(response)
        if (responseInfo.statusCode.toInt() != 200) {
            callbacks.printOutput("Poll for " + correlationId + " was unsuccessful: " + responseInfo.statusCode)
            return false
        }
        val responseStr = String(response)
        val responseBody = responseStr.split("\r\n\r\n".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()[1]
        try {
            val jsonObject = JSONObject(responseBody)
            val aesKey = jsonObject.getString("aes_key")
            val key = decryptAesKey(aesKey)
            if (!jsonObject.isNull("data")) {
                val data = jsonObject.getJSONArray("data")
                for (i in 0 until data.length()) {
                    val d = data.getString(i)
                    val decryptedData = decryptData(d, key)
                    val entry = LogEntry(decryptedData)
                    Logger.addEntry(entry)
                    callbacks.printOutput(entry.toString())
                }
            }
        } catch (ex: Exception) {
            callbacks.printOutput(ex.message)
        }
        return true
    }

    fun deregister() {
        callbacks.printOutput("Unregistering $correlationId")
        try {
            val deregisterData = JSONObject()
            deregisterData.put("correlation-id", correlationId)
            deregisterData.put("secret-key", secretKey)
            var request = """
                POST /deregister HTTP/1.1
                Host: $host
                User-Agent: Interact.sh Client
                Content-Type: application/json
                Content-Length: ${deregisterData.toString().length}
                
                """.trimIndent()
            if (authorization.isNotEmpty()) {
                request += "Authorization: $authorization\r\n"
            }
            request += """
                Connection: close
                
                $deregisterData
                """.trimIndent()
            callbacks.makeHttpRequest(host, port, useHttps, request.toByteArray(StandardCharsets.UTF_8))
        } catch (ex: Exception) {
            callbacks.printOutput(ex.message)
        }
    }

    // Fix the string up to 33 characters
    val interactDomain: String
        get() = if (correlationId.isEmpty()) {
            ""
        } else {
            var fullDomain: String = correlationId

            // Fix the string up to 33 characters
            val random = Random()
            while (fullDomain.length < 33) {
                fullDomain += (random.nextInt(26) + 'a'.code).toChar()
            }
            fullDomain += ".$host"
            fullDomain
        }

    fun generateKeys() {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()
        publicKey = kp.public
        privateKey = kp.private
    }

    private fun getPublicKey(): String {
        var pubKey = "-----BEGIN PUBLIC KEY-----\n"
        val chunks = splitStringEveryN(Base64.getEncoder().encodeToString(publicKey!!.encoded), 64)
        for (chunk in chunks) {
            pubKey += """
                $chunk
                
                """.trimIndent()
        }
        pubKey += "-----END PUBLIC KEY-----\n"
        return pubKey
    }

    private fun decryptAesKey(encrypted: String): String {
        val cipherTextArray = Base64.getDecoder().decode(encrypted)
        val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
        val oaepParams = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT)
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams)
        val decrypted = cipher.doFinal(cipherTextArray)
        return String(decrypted)
    }

    private fun splitStringEveryN(s: String, interval: Int): Array<String?> {
        val arrayLength = ceil(s.length / interval.toDouble()).toInt()
        val result = arrayOfNulls<String>(arrayLength)
        var j = 0
        val lastIndex = result.size - 1
        for (i in 0 until lastIndex) {
            result[i] = s.substring(j, j + interval)
            j += interval
        }
        result[lastIndex] = s.substring(j)
        return result
    }

    private fun decryptData(input: String, key: String): String {
        val cipherTextArray = Base64.getDecoder().decode(input)
        val iv = Arrays.copyOfRange(cipherTextArray, 0, 16)
        val cipherText = Arrays.copyOfRange(cipherTextArray, 16, cipherTextArray.size - 1)
        val ivSpec = IvParameterSpec(iv)
        val secretKeySpec = SecretKeySpec(key.toByteArray(), "AES")
        val cipher = Cipher.getInstance("AES/CFB/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec)
        val decrypted = cipher.doFinal(cipherText)
        return String(decrypted)
    }

}