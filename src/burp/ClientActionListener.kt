package burp

import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.util.concurrent.TimeUnit


object ClientActionListener : ActionListener {
    var running = true
    private var pollers = ArrayList<Thread>()
    override fun actionPerformed(e: ActionEvent) {
        BurpExtender.stdout.println("Generating New Client")
        try {
            val c = Client()
            c.generateKeys()
            val polling = Thread(Runnable {
                try {
                    if (c.registerClient()) {
                        BurpExtender.addClient(c)
                        while (running) {
                            if (!c.poll()) {
                                return@Runnable
                            }
                            TimeUnit.SECONDS.sleep(BurpExtender.pollTime)
                        }
                    } else {
                        BurpExtender.stdout.println("Error Registering Client")
                    }
                } catch (ex: Exception) {
                    BurpExtender.stderr.println(ex.message)
                }
            })
            pollers.add(polling)
            polling.start()
            TimeUnit.SECONDS.sleep(1)
            val domain = c.interactDomain
            BurpExtender.stdout.println("New domain is: $domain")
            // Copy new client domain to clipboard
            Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(domain), null)
        } catch (ex: Exception) {
            BurpExtender.stderr.println(ex.message)
        }
    }
}