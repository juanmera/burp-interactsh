package burp

import org.json.JSONException
import org.json.JSONObject

object Logger {
    private val log: MutableList<LogEntry> = ArrayList()
    var onChange: (() -> Unit)? = null

    fun getIndex(i: Int): LogEntry {
        return log[i]
    }

    fun addEntry(i: LogEntry) {
        log.add(i)
        onChange?.invoke()
    }

    fun clear() {
        log.clear()
        onChange?.invoke()
    }

    val size: Int get() = log.size

}

class LogEntry(event: String?) {
    var protocol: String
    var uid: String
    var details: String
    var address: String
    var timestamp: String

    init {
        val jsonObject = JSONObject(event)
        protocol = jsonObject.getString("protocol")
        uid = jsonObject.getString("unique-id")
        address = jsonObject.getString("remote-address")
        timestamp = jsonObject.getString("timestamp")
        details = processDetails(protocol, jsonObject)
    }

    @Throws(JSONException::class)
    private fun processDetails(protocol: String, obj: JSONObject): String {
        var result: String
        when (protocol) {
            "dns" -> {
                result = """
                Query Type: ${obj.getString("q-type")}
                
                
                """.trimIndent()
                result += """
                Request: 
                ${obj.getString("raw-request")}
                
                """.trimIndent()
                result += """
                Response: 
                ${obj.getString("raw-response")}
                
                """.trimIndent()
            }

            "http" -> {
                result = """
                    Request: 
                    ${obj.getString("raw-request")}
                    
                    """.trimIndent()
                result += """
                    Response: 
                    ${obj.getString("raw-response")}
                    
                    """.trimIndent()
            }

            "smtp" -> {
                result = """
                    SMTP From: ${obj.getString("smtp-from")}
                    
                    
                    """.trimIndent()
                result += """
                    Request: 
                    ${obj.getString("raw-request")}
                    
                    """.trimIndent()
            }

            else -> result = "UNSUPPORTED PROTOCOL"
        }
        return result
    }

    override fun toString(): String {
        return """
            Protocol: $protocol
            UID: $uid
            Address: $address
            Timestamp: $timestamp
            
            """.trimIndent()
    }
}