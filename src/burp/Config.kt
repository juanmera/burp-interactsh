package burp

import kotlin.math.max

const val SETTINGS_PREFIX = "burp-interactsh-"
const val DEFAULT_HOST = "oast.fun"
const val DEFAULT_PORT = 443
const val DEFAULT_POLLING_INTERVAL: Long = 30
const val DEFAULT_USE_HTTPS = true

object Config {
    var host: String
        get() = loadSetting("host")
        set(value) {
            if (value.isEmpty()) {
                throw IllegalArgumentException("Host cannot be  empty")
            }
            saveSetting("host", value)
        }

    var port: Int
        get() = try {
            loadSetting("port").toInt()
        } catch (ex: NumberFormatException) {
            DEFAULT_PORT
        }
        set(value) = saveSetting("port", max(value, 1).toString())

    var useHttps: Boolean
        get() = loadSetting("use-https").toBoolean()
        set(value) = saveSetting("use-https", value.toString())

    var authorization: String
        get() = loadSetting("authorization")
        set(value) = saveSetting("authorization", value)

    var onPollingIntervalChange: ((Long)->Unit)? = null
    var pollingInterval: Long
        get() = try {
            loadSetting("polling-interval").toLong()
        } catch (ex: NumberFormatException) {
            DEFAULT_POLLING_INTERVAL
        }
        set(value) {
            saveSetting("polling-interval", max(value, 1).toString())
            onPollingIntervalChange?.invoke(value)
        }

    fun init() {
        if (host.isEmpty() || port == 0) {
            host = DEFAULT_HOST
            port = DEFAULT_PORT
            useHttps = DEFAULT_USE_HTTPS
            pollingInterval = DEFAULT_POLLING_INTERVAL
        } else {
            onPollingIntervalChange?.invoke(pollingInterval)
        }
    }

    private fun saveSetting(name: String, value: String) {
        BurpExtender.callbacks.saveExtensionSetting(SETTINGS_PREFIX + name, value)
        BurpExtender.stdout.println("Setting $name to \"$value\"")
    }

    private fun loadSetting(name: String): String {
        return try {
            BurpExtender.callbacks.loadExtensionSetting(SETTINGS_PREFIX + name)
        } catch (ex: NullPointerException) {
            ""
        }
    }
}