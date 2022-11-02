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
        val generateURLButton = JButton("Generate URL")
        val clearLogButton = JButton("Clear Log")
        val pollingIntervalLabel = JLabel("Polling Interval: ")
        val pollingIntervalField = JTextField(Config.pollingInterval.toString(), 4)
        panel.add(generateURLButton)
        panel.add(clearLogButton)
        panel.add(pollingIntervalLabel)
        panel.add(pollingIntervalField)

        generateURLButton.addActionListener { ClientPool.create() }
        clearLogButton.addActionListener { Logger.clear() }
        pollingIntervalField.addActionListener {
            try {
                Config.pollingInterval = pollingIntervalField.text.toLong()
            } catch (_: NumberFormatException) {
            }
        }
        return panel
    }

    private fun createConfigPanel(): JPanel {
        // Configuration pane
        val configPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        val innerConfigPanel = JPanel()
        val serverField = JTextField(Config.host, 20)
        val portField = JTextField(Config.port.toString(), 20)
        val authorizationField = JTextField(Config.authorization, 20)
        val useHttpsField = JCheckBox("", Config.useHttps)
        val serverLabel = JLabel("Host: ")
        val portLabel = JLabel("Port: ")
        val authLabel = JLabel("Authorization: ")
        val useHttpsLabel = JLabel("Use HTTPS: ")
        val saveConfigurationButton = JButton("Save")

        innerConfigPanel.size = Dimension(80, 150)
        innerConfigPanel.layout = SpringLayout()
        serverLabel.labelFor = serverField
        portLabel.labelFor = portField
        authLabel.labelFor = authorizationField
        useHttpsLabel.labelFor = useHttpsField
        saveConfigurationButton.addActionListener {
            Config.host = serverField.text
            Config.port = try {
                portField.text.toInt()
            } catch (ex: NumberFormatException) {
                443
            }
            Config.authorization = authorizationField.text
            Config.useHttps = useHttpsField.isSelected
        }

        innerConfigPanel.add(serverLabel)
        innerConfigPanel.add(serverField)
        innerConfigPanel.add(portLabel)
        innerConfigPanel.add(portField)
        innerConfigPanel.add(authLabel)
        innerConfigPanel.add(authorizationField)
        innerConfigPanel.add(useHttpsLabel)
        innerConfigPanel.add(useHttpsField)
        innerConfigPanel.add(saveConfigurationButton)
        // Add a blank panel so that SpringUtilities can make a well shaped grid
        innerConfigPanel.add(JPanel())
        SpringUtilities.makeCompactGrid(innerConfigPanel, 5, 2, 6, 6, 6, 6)
        configPanel.add(innerConfigPanel)
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