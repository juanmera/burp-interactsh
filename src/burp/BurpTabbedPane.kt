package burp

import utils.SpringUtilities
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.FlowLayout
import javax.swing.*
import javax.swing.table.AbstractTableModel
import javax.swing.table.TableModel


class BurpTabbedPane : JTabbedPane() {
    init {
        val splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        val resultsPanel = JPanel()
        val tableSplitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        val logTable = LogTable(LogTableModel(), resultsPanel, tableSplitPane)
        val scrollPane = JScrollPane(logTable)

        addTab("Logs", splitPane)
        tableSplitPane.topComponent = scrollPane
        tableSplitPane.bottomComponent = resultsPanel
        splitPane.bottomComponent = tableSplitPane
        splitPane.topComponent = createLogUI()
        addTab("Configuration", createConfigPanel())
        Logger.onChange = {
            logTable.revalidate()
        }
    }

    private fun createLogUI(): JPanel {
        val panel = JPanel()
        val generateURL = JButton("Generate URL")
        val clearLog = JButton("Clear Log")
        val pollLabel = JLabel("Poll Time: ")
        val pollField = JTextField(Config.pollTime.toString(), 4)
        panel.add(generateURL)
        panel.add(clearLog)
        panel.add(pollLabel)
        panel.add(pollField)

        generateURL.addActionListener(ClientActionListener)
        clearLog.addActionListener { Logger.clear() }
        pollField.addActionListener {
            try {
                BurpExtender.pollTime = pollField.text.toLong()
            } catch (_: NumberFormatException) {
            }
        }
        return panel
    }

    private fun createConfigPanel(): JPanel {
        // Configuration pane
        val configPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        val innerConfig = JPanel()
        val serverText = JTextField(Config.host, 20)
        val portText = JTextField(Config.port.toString(), 20)
        val authText = JTextField(Config.auth, 20)
        val useHttpsBox = JCheckBox("", Config.useHttps)
        val serverLabel = JLabel("Host: ")
        val portLabel = JLabel("Port: ")
        val authLabel = JLabel("Authorization: ")
        val useHttpsLabel = JLabel("Use HTTPS: ")
        val updateConfigButton = JButton("Save")

        innerConfig.size = Dimension(80, 150)
        innerConfig.layout = SpringLayout()
        serverLabel.labelFor = serverText
        portLabel.labelFor = portText
        authLabel.labelFor = authText
        useHttpsLabel.labelFor = useHttpsBox
        updateConfigButton.addActionListener {
            Config.host = serverText.text
            Config.port = try {
                portText.text.toInt()
            } catch (ex: NumberFormatException) {
                443
            }
            Config.auth = authText.text
            Config.useHttps = useHttpsBox.isSelected
        }

        innerConfig.add(serverLabel)
        innerConfig.add(serverText)
        innerConfig.add(portLabel)
        innerConfig.add(portText)
        innerConfig.add(authLabel)
        innerConfig.add(authText)
        innerConfig.add(useHttpsLabel)
        innerConfig.add(useHttpsBox)
        innerConfig.add(updateConfigButton)
        // Add a blank panel so that SpringUtilities can make a well shaped grid
        innerConfig.add(JPanel())
        SpringUtilities.makeCompactGrid(innerConfig, 5, 2, 6, 6, 6, 6)
        configPanel.add(innerConfig)
        return configPanel
    }
}

class LogTable(tableModel: TableModel, private val resultsPanel: JPanel, private val tableSplitPane: JSplitPane) :
    JTable(tableModel) {
    override fun changeSelection(row: Int, col: Int, toggle: Boolean, extend: Boolean) {
        // show the log entry for the selected row
        val ie = Logger.getIndex(row)
        resultsPanel.removeAll() // Refresh pane
        resultsPanel.layout = BorderLayout() //give your JPanel a BorderLayout
        val text = JTextArea(ie.details)
        val scroll = JScrollPane(text) //place the JTextArea in a scroll pane
        resultsPanel.add(scroll, BorderLayout.CENTER) //add the JScrollPane to the panel
        tableSplitPane.revalidate()
        super.changeSelection(row, col, toggle, extend)
    }
}

class LogTableModel : AbstractTableModel() {
    override fun getRowCount(): Int {
        return Logger.size
    }

    override fun getColumnCount(): Int {
        return 4
    }

    override fun getColumnName(columnIndex: Int): String {
        return when (columnIndex) {
            0 -> "Entry"
            1 -> "Type"
            2 -> "Address"
            3 -> "Time"
            else -> ""
        }
    }

    override fun getColumnClass(columnIndex: Int): Class<*> {
        return String::class.java
    }

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val ie = Logger.getIndex(rowIndex)
        return when (columnIndex) {
            0 -> ie.uid
            1 -> ie.protocol
            2 -> ie.address
            3 -> ie.timestamp
            else -> ""
        }
    }
}