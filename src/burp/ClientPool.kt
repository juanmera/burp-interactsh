package burp

import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import kotlin.math.max
import java.util.concurrent.TimeUnit


object ClientPool {
    private var running = true
    private var pollingInterval: Long = 1
    private var threads = ArrayList<Thread>()

    fun init() {
        Config.onPollingIntervalChange = { pollingInterval = max(it, 1) }
    }

    fun stopAll() {
        running = false
        for (p in threads) {
            p.join()
        }
    }

    fun create() {
        Callbacks.printOutput("Starting new client thread")
        try {
            val thread = Thread(ClientRunnable())
            threads.add(thread)
            thread.start()
        } catch (ex: Exception) {
            Callbacks.printError(ex.message)
        }
    }

    internal class ClientRunnable : Runnable {
        override fun run() {
            try {
                val c = Client()
                c.generateKeys()
                if (c.registerClient()) {
                    val domain = c.getDomain()
                    Callbacks.printOutput("Domain: $domain")
                    // Copy domain to the clipboard
                    Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(domain), null)
                    do {
                        TimeUnit.SECONDS.sleep(pollingInterval)
                    } while (running && c.poll())
                    c.deregister()
                } else {
                    Callbacks.printOutput("Error registering client")
                }
            } catch (ex: Exception) {
                Callbacks.printError(ex.message)
            }
        }
    }
}
