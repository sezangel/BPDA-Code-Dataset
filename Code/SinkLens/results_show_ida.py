from typing import NamedTuple
import idc
import ida_auto
import json
import idaapi
import idautils
import datetime
from PyQt5 import QtWidgets
from idc import *

from idaapi import (Choose, PluginForm, Form)

class ResultChooser(Choose):
    def __init__(self, title, matches):
        columns = [ ["Line", 8], ["Local Address", 12], ["Local Name", 24], ["Loop Address", 12], ["Is Copy Function", 16], ["Probality", 16]]

        Choose.__init__(self, title, columns, flags = Choose.CH_MULTI)
        self.n = 0
        self.icon = -1
        self.selcount = 0
        self.modal = False
        self.items = []
        self.selected_items = []

        for i in range(len(matches)):
            
            ea, name, loop_ea, flag, ratio = matches[i]
            
            line = ["%03d" % i, "0x%08x" % ea, name, "0x%08x" % loop_ea, str(flag), str(ratio)]

            self.items.append(line)

    def GetItems(self):
        return self.items
        
    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def OnDeleteLine(self, n):
        del self.items[n]
        return n

    def OnRefresh(self, n):
        return n

    def OnSelectLine(self, n):
        self.selcount += 1
        index = int(n[0])
        row = self.items[index]
        ea = int(row[1], 16)
        jumpto(ea, -1, 1)

    def OnSelectionChange(self, sel_list):
        self.selected_items = sel_list
class CopyFunctionViewer(PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

        self.browser = None
        self.layout = None 
        return 1
    def PopulateForm(self):
        self.layout = QtWidgets.QVBoxLayout()
        self.browser = QtWidgets.QTextBrowser()
        self.browser.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
        self.browser.setHtml(self.text)
        self.browser.setReadOnly(True)
        self.browser.setFontWeight(12)
        self.layout.addWidget(self.browser)
        self.parent.setLayout(self.layout)

    def Show(self, text, title):
        self.text = text
        return PluginForm.Show(self, title)

if __name__ == "__main__":
    items = {}
    line = []
    for i in range(20):
        line = []
        line.append(i)
        line.append("function name")
        line.append("flag")
        line.append("probality")
        items[i] = line
    
    c= ResultChooser("Copy function", items)
    c.Show()
