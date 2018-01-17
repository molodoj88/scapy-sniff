import sys
from PyQt5 import QtCore, QtWidgets, QtGui
from PyQt5.QtCore import Qt, QModelIndex, QElapsedTimer
from PyQt5.QtNetwork import QNetworkInterface
import logging
from sp import Sniffer
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from PyQt5.QtWidgets import QSizePolicy


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
        :param pkt: список [ip источника, ip назначения, порт источника, порт назначения, длина сегмента]
        '''
        timestamp = (-self.timer_start + self.timer.elapsed()) / 1000
        # потоки
        flows = list(self.model.flows.keys())

        # проверяем, нет ли такого потока уже
        # если есть, прибавляем к счётчику пакетов 1
        # если нет, добавляем новый поток
        flow_desc = ((pkt[0], pkt[1]), (pkt[2], pkt[3]))
        segment_len = pkt[4]
        if flow_desc in flows:
            self.model.flows[flow_desc]['count'] += 1
            self.model.flows[flow_desc]['len_seq'].append(segment_len,)
            self.model.flows[flow_desc]['data_len'] += segment_len
            self.model.flows[flow_desc]['timestamp_list'].append(timestamp)
            topLeft = self.model.createIndex(self.model.flows[flow_desc]['id'], 2)
            self.model.dataChanged.emit(topLeft, topLeft)
        else:
            self.model.flows[flow_desc] = {'id': self.model.flow_id, 'count': 1,
                                           'len_seq': [segment_len, ],
                                           'data_len': segment_len,
                                           'timestamp_list': [timestamp, ]}
            self.model.insertRows(len(self.model.flows) - 1, 1)
            topLeft = self.model.createIndex(self.model.flows[flow_desc]['id'], 0)
            bottomRight = self.model.createIndex(self.model.flows[flow_desc]['id'], 2)
            self.model.dataChanged.emit(topLeft, bottomRight)
            self.model.flow_id += 1

    def init_ui(self):
        self.resize(1000, 800)
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
        self.table = MyView()
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setMinimumSectionSize(200)
        self.table.resizeColumnsToContents()
        self.table.setModel(self.model)
        layout.addWidget(self.table)
        self.table.context_menu_pressed.connect(self.on_context_menu_pressed)

    def on_context_menu_pressed(self, event):
        index = self.table.indexAt(event.pos())
        flow_id = index.row()
        flow = self.model.get_flow_by_id(flow_id)
        data = self.model.flows[flow]['timestamp_list']
        modal_window = ModalPlotWindow(self)
        modal_window.setWindowTitle('Гистограмма')
        title = "Распределение интервалов между пакетами для потока\n{}:{}->{}:{}".format(flow[0][0],
                                                                           flow[1][0],
                                                                           flow[0][1],
                                                                           flow[1][1])
        modal_window.canvas.plot_histogram(title, data)
        modal_window.show()

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


class MyView(QtWidgets.QTableView):
    context_menu_pressed = QtCore.pyqtSignal(QtCore.QEvent)

    def __init__(self, parent=None):
        super(MyView, self).__init__(parent=parent)

    def contextMenuEvent(self, event):
        menu = QtWidgets.QMenu()
        open_plot_window_action = menu.addAction("Построить графики для потока")
        action = menu.exec_(event.globalPos())
        if action == open_plot_window_action:
            self.context_menu_pressed.emit(event)


class MyModel(QtCore.QAbstractTableModel):
    def __init__(self, parent=None, logger=None):
        super(MyModel, self).__init__(parent)
        self.columnNames = ['Source', 'Destination', 'Count', 'Mean length', 'Ave. speed']
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
            flow_desc = self.get_flow_by_id(index.row())
            if index.column() == 0:
                return "{}: {}".format(flow_desc[0][0], flow_desc[1][0])
            if index.column() == 1:
                return "{}: {}".format(flow_desc[0][1], flow_desc[1][1])
            if index.column() == 2:
                return str(self.flows[flow_desc]["count"])
            if index.column() == 3:
                return str(self.flows[flow_desc]['data_len'] / len(self.flows[flow_desc]['len_seq']))
            if index.column() == 4:
                min_timestamp = min(self.flows[flow_desc]['timestamp_list'])
                max_timestamp = max(self.flows[flow_desc]['timestamp_list'])
                return str(self.flows[flow_desc]['data_len'] / max_timestamp - min_timestamp)

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

    def get_flow_by_id(self, id):
        # получаем ключ для потока по его id
        for k, v in self.flows.items():
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


class PlotCanvas(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi)

        FigureCanvas.__init__(self, fig)
        self.setParent(parent)

        FigureCanvas.setSizePolicy(self,
                                   QSizePolicy.Expanding,
                                   QSizePolicy.Expanding)
        FigureCanvas.updateGeometry(self)

    def plot_histogram(self, title, data):
        ax = self.figure.add_subplot(111)
        ax.grid()
        ax.hist(data, normed=True)
        ax.set_title(title)
        self.draw()


class ModalPlotWindow(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super(ModalPlotWindow, self).__init__(parent)
        self.setWindowFlags(QtCore.Qt.Dialog | QtCore.Qt.WindowSystemMenuHint)
        self.setWindowModality(QtCore.Qt.WindowModal)
        layout = QtWidgets.QVBoxLayout(self)
        self.canvas = PlotCanvas(self)
        layout.addWidget(self.canvas)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    sys.exit(app.exec_())
