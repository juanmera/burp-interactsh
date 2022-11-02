package burp

import java.awt.Component
import javax.swing.JMenuItem
import javax.swing.SwingUtilities

lateinit var Callbacks: IBurpExtenderCallbacks

@Suppress("unused")
class BurpExtender : IBurpExtender, IExtensionStateListener, IContextMenuFactory, ITab {
    private var mainPane: Component? = null

    override fun registerExtenderCallbacks(cb: IBurpExtenderCallbacks) {
        Callbacks = cb
        Callbacks.setExtensionName("OAST")
        Callbacks.printOutput("Loading Extension")
        // ClientPool needs to be initialized before Config
        ClientPool.init()
        Config.init()
        Callbacks.registerExtensionStateListener(this@BurpExtender)
        Callbacks.registerContextMenuFactory(this@BurpExtender)
        mainPane = BurpTabbedPane()

        SwingUtilities.invokeLater {
            Callbacks.customizeUiComponent(mainPane)
            Callbacks.addSuiteTab(this@BurpExtender)
        }
    }

    override fun extensionUnloaded() {
        ClientPool.stopAll()
        Callbacks.printOutput("Extension Unloaded")
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