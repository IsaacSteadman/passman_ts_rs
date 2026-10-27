package com.firaxite.passman

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/** A request failed; `kind` is "offline", "key-changed" or "error". */
class TransportException(message: String, val kind: String) : IOException(message)

class HttpResult(
    val status: Int,
    val statusText: String,
    val headers: List<Pair<String, String>>,
    val body: ByteArray,
)

/**
 * Sends the pages' requests to the server, and only to it. With a pinned key,
 * TLS fails before anything (credentials included) is sent unless the server
 * presents that key, in a certificate Android trusts as well.
 */
class ServerTransport(private val origin: String, private val pinnedKey: String?) {
    private val socketFactory: SSLSocketFactory? = pinnedKey?.let { pin ->
        val system = systemTrustManager()
        // Android's checks first, then the pin: this only ever trusts less
        val pinning = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
                system.checkClientTrusted(chain, authType)

            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                system.checkServerTrusted(chain, authType)
                if (publicKeyFingerprint(chain[0]) != pin) throw CertificateException(KEY_CHANGED)
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> = system.acceptedIssuers
        }
        SSLContext.getInstance("TLS").apply { init(null, arrayOf(pinning), null) }.socketFactory
    }

    fun request(url: String, method: String, headers: List<Pair<String, String>>, body: ByteArray?): HttpResult {
        val target = URL(url)
        if (originOf(target) != origin) throw TransportException("Only the Passman server can be reached.", "error")
        if (method !in METHODS) throw TransportException("Unsupported method $method", "error")
        val connection = target.openConnection() as HttpURLConnection
        try {
            if (connection is HttpsURLConnection && socketFactory != null) connection.sslSocketFactory = socketFactory
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.connectTimeout = 15_000
            connection.readTimeout = 60_000
            connection.requestMethod = method
            for ((name, value) in headers)
                if (name.lowercase() !in RESTRICTED_HEADERS) connection.addRequestProperty(name, value)
            if (body != null) {
                connection.doOutput = true
                connection.setFixedLengthStreamingMode(body.size)
                connection.outputStream.use { it.write(body) }
            }
            val status = connection.responseCode
            val stream = if (status >= 400) connection.errorStream else connection.inputStream
            return HttpResult(
                status,
                connection.responseMessage ?: "",
                connection.headerFields.flatMap { (name, values) ->
                    if (name == null) emptyList() else values.map { name to it }
                },
                stream?.use { readLimited(it) } ?: ByteArray(0),
            )
        } catch (e: TransportException) {
            throw e
        } catch (e: IOException) {
            if (generateSequence<Throwable>(e) { it.cause }.any { it.message == KEY_CHANGED })
                throw TransportException(
                    "The server's certificate key isn't the one Passman was set up to trust. " +
                        "If the server's owner changed it, choose the server again under Server Settings.",
                    "key-changed",
                )
            throw TransportException(e.message ?: e.toString(), "offline")
        } finally {
            connection.disconnect()
        }
    }

    companion object {
        private const val KEY_CHANGED = "passman: certificate key changed"
        private val METHODS = setOf("GET", "HEAD", "POST", "PUT", "DELETE")
        private val RESTRICTED_HEADERS = setOf("host", "connection", "content-length", "transfer-encoding")
        private const val MAX_BODY = 256 * 1024 * 1024

        fun originOf(url: URL): String {
            val port = if (url.port == -1 || url.port == url.defaultPort) "" else ":${url.port}"
            return "${url.protocol.lowercase()}://${url.host.lowercase()}$port"
        }

        fun systemTrustManager(): X509TrustManager {
            val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            factory.init(null as KeyStore?)
            return factory.trustManagers.filterIsInstance<X509TrustManager>().first()
        }

        /** The SHA-256 of the certificate's SubjectPublicKeyInfo. */
        fun publicKeyFingerprint(certificate: X509Certificate): String =
            certificate.publicKey.encoded.sha256().toColonHex()

        fun readLimited(stream: InputStream, limit: Int = MAX_BODY): ByteArray {
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = stream.read(buffer)
                if (read < 0) break
                out.write(buffer, 0, read)
                if (out.size() > limit) throw IOException("response too large")
            }
            return out.toByteArray()
        }
    }
}
