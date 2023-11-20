import subprocess
import os
import idaapi
from idaapi import Choose
import idautils
import idc
from .vmrunrunner import *
import json

vms_list = []

class chooser_handler_t(idaapi.action_handler_t):
    def __init__(self, vm_cmd):
        idaapi.action_handler_t.__init__(self)
        self.vm_cmd = vm_cmd

    def activate(self, ctx):
        global vms_list
        vm_path = vms_list[ctx.chooser_selection[0]][1]
        vmrun_it(vm_path, self.vm_cmd)

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if idaapi.is_chooser_widget(ctx.widget_type) else idaapi.AST_DISABLE_FOR_WIDGET

# TODO, command/script exec interface, list snapshots, pause/unpause, other vmrun stuff
action_dict = {
                "vm_vmware_start":"Start VMWare",
                "vm_start":"Start VM",
                "vm_suspend":"Suspend VM",
                "vm_revert":"Revert to a previous snapshot",
                "vm_take_snapshot":"Take a snapshot",
                "vm_copy_debug_stub":"Copy remote debugger to VM",
                "vm_start_debug_stub_in_vm":"Start remote debugger in VM",
                "vm_copy_this_file_to_guest":"Copy current file to VM"
                }

for action_name, label in action_dict.items():
    desc = idaapi.action_desc_t(action_name, label, chooser_handler_t(action_name))
    idaapi.register_action(desc)


def vms_list():
    global vms_list
    vms_list = []
    config_path = os.path.dirname(__file__) + '/config.json'
    config_json = json.load(open(config_path))
    vms_path = config_json["vms_path"]
    with os.scandir(vms_path) as vmdir_items:
        for entry in vmdir_items:
            if entry.name.endswith('.vmwarevm') and entry.is_dir():
                for file in os.listdir(entry):
                    if file.endswith(".vmx"):
                        vm_name = file
                        vms_list.append([vm_name, entry.path + "/" + vm_name])

    return vms_list

class VMChoose(Choose):
    def __init__(self, title):
        Choose.__init__(
                self,
                title,
                [
                    ["VM Name",  20 | Choose.CHCOL_PLAIN],
                    ["Path",     30 | Choose.CHCOL_PATH]
                ])
        self.items = []
        self.icon = 41

    def OnPopup(self, widget, popup_handle):
        for action_name in action_dict.keys():
            idaapi.attach_action_to_popup(self.GetWidget(), None, action_name)

    def OnInit(self):
        self.items = vms_list()

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        print(self.items[n][0])
        return (Choose.NOTHING_CHANGED, )

    def OnRefresh(self, n):
        self.OnInit()
        return [Choose.ALL_CHANGED] + self.adjust_last_item(n)

    def OnClose(self):
        print("closed VMChooser", self.title)

def vmchooser():
    
    c = VMChoose("VM Chooser")
    c.Show()

class VMs(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        vmchooser()

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
        
