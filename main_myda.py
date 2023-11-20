import idaapi
import os
from myda.vms import *

def add_menu():

    # create custom menus - top level and sub menu
    idaapi.create_menu("myda_menu", "myda", "")
    idaapi.create_menu("vm_submenu", "VMs", "myda/")

    ACTION_NAME_1 = "action1"
    
    d1 = idaapi.action_desc_t(
            ACTION_NAME_1,
            "Run the VMs script",
            VMs())

    idaapi.register_action(d1)

    idaapi.attach_action_to_menu(
            "myda/VMs/",
            ACTION_NAME_1,
            idaapi.SETMENU_INS)

class myda_plugmod_t(idaapi.plugmod_t):
    def run(self, arg):
        # on init, create the menu
        add_menu()
        return 0

class myda_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_MULTI
    help = "myda help"
    wanted_name = "myda"
    wanted_hotkey = ""

    def init(self):
        return myda_plugmod_t()

def PLUGIN_ENTRY():
    return myda_plugin_t()
