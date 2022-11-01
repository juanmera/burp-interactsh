package burp

const val SETTINGS_PREFIX = "burp-interactsh-"
const val DEFAULT_HOST = "oast.fun"
const val DEFAULT_PORT = 443
const val DEFAULT_POLL_TIME: Long = 30
const val DEFAULT_USE_HTTPS = true

object Config {
    var host: String
        get() = loadSetting("host")
        set(value) = saveSetting("host", value)

    var port: Int
        get() = try {
            loadSetting("port").toInt()
        } catch (ex: NumberFormatException) {
            DEFAULT_PORT
        }
        set(value) = saveSetting("port", value.toString())

    var useHttps: Boolean
        get() = loadSetting("use-https").toBoolean()
        set(value) = saveSetting("use-https", value.toString())

    var auth: String
        get() = loadSetting("authorization")
        set(value) = saveSetting("authorization", value)

    var pollTime: Long
        get() = try {
            loadSetting("poll-time").toLong()
        } catch (ex: NumberFormatException) {
            DEFAULT_POLL_TIME
        }
        set(value) = saveSetting("poll-time", value.toString())

    fun generate() {
        if (host.isEmpty() || port == 0) {
            host = DEFAULT_HOST
            port = DEFAULT_PORT
            useHttps = DEFAULT_USE_HTTPS
            pollTime = DEFAULT_POLL_TIME
        }
    }

    private fun saveSetting(name: String, value: String) {
        BurpExtender.callbacks.saveExtensionSetting(SETTINGS_PREFIX + name, value)
    }

    private fun loadSetting(name: String): String {
        return try {
            BurpExtender.callbacks.loadExtensionSetting(SETTINGS_PREFIX + name)
        } catch (ex: NullPointerException) {
            ""
        }
    }
}