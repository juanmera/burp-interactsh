package burp

import java.awt.Component
import java.io.PrintWriter
import javax.swing.JMenuItem
import javax.swing.SwingUtilities

class BurpExtender : IBurpExtender, IExtensionStateListener, IContextMenuFactory, ITab {
    companion object {
        lateinit var callbacks: IBurpExtenderCallbacks
        lateinit var stdout: PrintWriter
        lateinit var stderr: PrintWriter

        fun analyzeResponse(response: ByteArray): IResponseInfo {
            return callbacks.helpers.analyzeResponse(response)
        }
    }

    private var mainPane: Component? = null

    override fun registerExtenderCallbacks(cb: IBurpExtenderCallbacks) {
        callbacks = cb
        callbacks.setExtensionName("OAST")
        stdout = PrintWriter(callbacks.stdout, true)
        stderr = PrintWriter(callbacks.stderr, true)
        stdout.println("Loading Extension")
        // ClientPool needs to be initialized before Config
        ClientPool.init()
        Config.init()
        callbacks.registerExtensionStateListener(this@BurpExtender)
        callbacks.registerContextMenuFactory(this@BurpExtender)
        mainPane = BurpTabbedPane()

        SwingUtilities.invokeLater {
            callbacks.customizeUiComponent(mainPane)
            callbacks.addSuiteTab(this@BurpExtender)
        }
    }

    override fun extensionUnloaded() {
        ClientPool.stopAll()
        stdout.println("Extension Unloaded")
    }

    override fun createMenuItems(invocation: IContextMenuInvocation?): MutableList<JMenuItem> {
        val menuList: MutableList<JMenuItem> = ArrayList()
        val item = JMenuItem("Generate URL")
        item.addActionListener { ClientPool.create() }
        menuList.add(item)
        return menuList
    }

    override fun getTabCaption(): String {
        return "OAST"
    }

    override fun getUiComponent(): Component {
        return mainPane!!
    }
}