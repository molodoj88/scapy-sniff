import sys
from PyQt5 import QtCore, QtWidgets, QtGui
from PyQt5.QtCore import QThread


class MainWindow(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.init_ui()

    def init_ui(self):
        self.resize(800, 600)
        self.setWindowTitle('Sniffer')
        self.main_widget = QtWidgets.QWidget()
        self.main_layout = QtWidgets.QHBoxLayout()
        self.setLayout(self.main_layout)
        self.main_layout.addWidget(self.main_widget)
        self.init_table(self.main_widget)
        self.show()

    def init_table(self, widget):
        layout = QtWidgets.QHBoxLayout(widget)
        self.model = MyModel()
        self.table = QtWidgets.QTableView()
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        self.table.resizeColumnsToContents()
        self.table.setModel(self.model)
        layout.addWidget(self.table)


class MyModel(QtCore.QAbstractTableModel):
    def __init__(self, parent=None):
        super(MyModel, self).__init__(parent)

    def rowCount(self, parent=None, *args, **kwargs):
        return 5

    def columnCount(self, parent=None, *args, **kwargs):
        return 4


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    sys.exit(app.exec_())
