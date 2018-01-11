import sys
from PyQt5 import QtCore, QtWidgets, QtGui
from PyQt5.QtCore import Qt, QModelIndex, QElapsedTimer
from PyQt5.QtNetwork import QNetworkInterface
import logging
from sp import Sniffer


class MainWindow(QtWidgets.QMainWindow):
    signal_start_sniffer = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)

        self.init_ui()

        # Открываем поток для сниффера
        self.worker = Sniffer()
        self.sniffer_thread = QtCore.QThread()
        self.worker.moveToThread(self.sniffer_thread)

        self.signal_start_sniffer.connect(self.worker.do_sniff)
        self.worker.signal_pkt_received.connect(self.update_flows)
        for iface in QNetworkInterface.allInterfaces():
            self.log_message(iface.name())

        self.timer = QElapsedTimer()

    def start_sniff(self):
        self.sniffer_thread.start()
        self.timer_start = self.timer.elapsed()
        self.signal_start_sniffer.emit()

    def update_flows(self, pkt):
        '''
        Обновляем словарик с потоками при получении нового пакета
        :param pkt: список [ip источника, ip назначения, порт источника, порт назначения]
        '''
        self.log_message("{} s".format((self.timer_start - self.timer.elapsed()) / 1000))
        # потоки
        flows = list(self.model.flows.keys())

        # проверяем, нет ли такого потока уже
        # если есть, прибавляем к счётчику пакетов 1
        # если нет, добавляем новый поток
        flow_desc = ((pkt[0], pkt[1]), (pkt[2], pkt[3]))
        if flow_desc in flows:
            self.model.flows[flow_desc]['count'] += 1
            topLeft = self.model.createIndex(self.model.flows[flow_desc]['id'], 2)
            self.model.dataChanged.emit(topLeft, topLeft)
        else:
            self.model.flows[flow_desc] = {'id': self.model.flow_id, 'count': 1}
            self.model.insertRows(len(self.model.flows) - 1, 1)
            topLeft = self.model.createIndex(self.model.flows[flow_desc]['id'], 0)
            bottomRight = self.model.createIndex(self.model.flows[flow_desc]['id'], 2)
            self.model.dataChanged.emit(topLeft, bottomRight)
            self.model.flow_id += 1

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
        self.model = MyModel(logger=self.log_message)
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
    def __init__(self, parent=None, logger=None):
        super(MyModel, self).__init__(parent)
        self.columnNames = ['Source', 'Destination', 'Count']
        self.flows = {}
        self.flow_id = 0
        self.logger = logger

    def rowCount(self, parent=None, *args, **kwargs):
        return len(self.flows)

    def columnCount(self, parent=None, *args, **kwargs):
        return len(self.columnNames)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            self.logger('not valid')
            return None
        if role == Qt.DisplayRole:
            flow_desc = self.get_flow_by_id(self.flows, index.row())
            if index.column() == 0:
                return "{}: {}".format(flow_desc[0][0], flow_desc[1][0])
            if index.column() == 1:
                return "{}: {}".format(flow_desc[0][1], flow_desc[1][1])
            if index.column() == 2:
                return str(self.flows[flow_desc]["count"])

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
        self.endInsertRows()
        return True

    def get_flow_by_id(self, d, id):
        # получаем ключ для потока по его id
        for k, v in d.items():
            if v['id'] == id:
                return k


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
