import sys
from PyQt5 import QtCore, QtWidgets, QtGui
from PyQt5.QtCore import Qt, QModelIndex
from PyQt5.QtCore import QThread


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)

        self.init_ui()

    def init_ui(self):
        self.resize(800, 600)
        self.setWindowTitle('Sniffer')
        self.main_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.main_widget)
        self.init_table(self.main_widget)
        self.show()

    def init_table(self, widget):
        layout = QtWidgets.QHBoxLayout(widget)
        self.model = MyModel()
        self.table = QtWidgets.QTableView()
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setMinimumSectionSize(200)
        self.table.resizeColumnsToContents()
        self.table.setModel(self.model)
        layout.addWidget(self.table)

    def init_toolbar(self):
        self.addToolBar('Start')


class MyModel(QtCore.QAbstractTableModel):
    def __init__(self, parent=None):
        super(MyModel, self).__init__(parent)
        self.flows = []
        self.columnNames = ['Source IP: port', 'Destination IP: port', 'Packet Count']

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

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    sys.exit(app.exec_())
