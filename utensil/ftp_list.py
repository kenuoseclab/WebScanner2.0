import os

import PyQt5
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QListWidget


class QFtp_list(QListWidget):

    drop_release = pyqtSignal(PyQt5.QtGui.QDropEvent)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            filename = event.mimeData().urls()[0].fileName()  # 只有文件名
            basename, ext = os.path.splitext(filename)  # 文件名和后缀
            ext = ext.upper()
            if ext == ".TXT":  # 只接收TXT文件
                event.acceptProposedAction()
            else:
                event.ignore()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        event.accept()

    def dropEvent(self, event):
        self.drop_release.emit(event)




