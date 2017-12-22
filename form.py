import sys
from PyQt5 import QtCore, QtWidgets, QtGui
from PyQt5.QtCore import Qt, QModelIndex
import logging
from sp import Sniffer


class MainWindow(QtWidgets.QMainWindow):
    signal_start_sniffer = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)

        self.init_ui()

        self.worker = Sniffer()
        self.sniffer_thread = QtCore.QThread()
        self.worker.moveToThread(self.sniffer_thread)

        self.signal_start_sniffer.connect(self.worker.do_sniff)
        self.worker.signal_send_msg.connect(self.log_message)

    def start_sniff(self):
        self.sniffer_thread.start()
        self.signal_start_sniffer.emit()

    def init_ui(self):
        self.resize(800, 600)
        self.setWindowTitle('Sniffer')
        self.main_widget = QtWidgets.QWidget()
        self.main_layout = QtWidgets.QVBoxLayout(self.main_widget)
        self.setCentralWidget(self.main_widget)
        self.init_table(self.main_layout)
        self.init_toolbar()
        self.init_log(self.main_layout)
        self.show()

    def init_table(self, layout):
        self.model = MyModel()
        self.table = QtWidgets.QTableView()
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setMinimumSectionSize(200)
        self.table.resizeColumnsToContents()
        self.table.setModel(self.model)
        layout.addWidget(self.table)

    def init_log(self, layout):
        self.log_visible = True
        self.logger = TextLogger(self)
        self.logger.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', "%Y-%m-%d %H:%M:%S"))
        logging.getLogger().addHandler(self.logger)
        logging.getLogger().setLevel(logging.DEBUG)
        layout.addWidget(self.logger.widget)

    def init_toolbar(self):
        self.toolbar = self.addToolBar('Start')
        # Кнопка запуска
        start_action = QtWidgets.QAction(QtGui.QIcon('images/play-button-icon.png'), 'Start', self)
        start_action.triggered.connect(self.start_button_clicked)
        self.toolbar.addAction(start_action)
        # Скрыть/показать лог
        self.hide_log_action = QtWidgets.QAction(QtGui.QIcon('images/hide-log-button-icon.png'), 'Hide/Show log', self)
        self.hide_log_action.triggered.connect(self.hide_log_button_clicked)
        self.toolbar.addAction(self.hide_log_action)

    def start_button_clicked(self):
        self.log_message('Start sniffing')
        self.start_sniff()

    def log_message(self, msg):
        """
        Везде, где нужно вывести сообщение в лог, вызываем эту функцию
        """
        logging.debug(msg)

    def hide_log_button_clicked(self):
        if self.log_visible:
            self.log_visible = False
            self.logger.widget.setVisible(False)
            self.hide_log_action.setChecked(True)
        else:
            self.log_visible = True
            self.logger.widget.setVisible(True)
            self.hide_log_action.setChecked(False)


class MyModel(QtCore.QAbstractTableModel):
    def __init__(self, parent=None):
        super(MyModel, self).__init__(parent)
        self.columnNames = ['Source IP: port', 'Destination IP: port', 'Packet Count']
        self.flows = [dict(zip(self.columnNames, ("192.168.10.1", "10.1.2.5", "223")))]

    def rowCount(self, parent=None, *args, **kwargs):
        return len(self.flows)

    def columnCount(self, parent=None, *args, **kwargs):
        return len(self.columnNames)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        if 0 <= index.row() < len(self.flows):
            return None

        if role == Qt.DisplayRole:

            for i in range(self.columnCount()):
                if index.columns() == i:
                    return self.flows[index.row()][self.columnNames[i]]

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None

        if orientation == Qt.Horizontal:
            for i in range(self.columnCount()):
                if section == i:
                    return self.columnNames[i]

        return None

    def insertRows(self, pos=0, count=1, parent=None):
        self.beginInsertRows(QModelIndex(), pos, pos + count - 1)

        rowToInsert = dict(zip(self.columnNames, [""] * self.columnCount()))

        for row in range(count):
            self.flows.insert(row + pos, rowToInsert)

        self.endInsertRows()
        return True

    def setData(self, index, value, role=Qt.EditRole):
        if role != Qt.EditRole:
            return False

        if index.isValid() and 0 <= index.row() < len(self.flows):
            flow = self.flows[index.row()]

            for i in range(self.columnCount()):
                if index.column() == i:
                    flow[self.columnNames[i]] = value
                    return True

            self.dataChanged.emit(index, index)
            return True

        return False


class TextLogger(logging.Handler):
    """
    Handler for logger
    """
    def __init__(self, parent):
        logging.Handler.__init__(self)
        self.widget = QtWidgets.QGroupBox('Log')
        layout = QtWidgets.QVBoxLayout(self.widget)
        self.text_widget = QtWidgets.QTextEdit()
        self.text_widget.setReadOnly(True)
        layout.addWidget(self.text_widget)

    def emit(self, record):
        msg = self.format(record)
        self.text_widget.append(msg)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    sys.exit(app.exec_())
